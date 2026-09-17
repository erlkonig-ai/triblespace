use cubecl::client::ComputeClient;
use cubecl::prelude::*;
use triblespace_core::blob::encodings::succinctarchive::{
    SuccinctRotation, WaveletMatrixFreezeBackend,
};

use crate::{FreezeGeometry, GpuFreezeError};

const BLOCK_SIZE: u32 = super::BLOCK_SIZE;
const THREADS: u32 = super::THREADS;

fn read_packed_u32(bytes: &[u8], index: usize) -> Result<u32, GpuFreezeError> {
    let start = index
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or(GpuFreezeError::GeometryOverflow("host packed byte offset"))?;
    let end = start
        .checked_add(std::mem::size_of::<u32>())
        .ok_or(GpuFreezeError::GeometryOverflow("host packed byte end"))?;
    let word = bytes.get(start..end).ok_or(GpuFreezeError::ReadbackSize {
        expected: end,
        actual: bytes.len(),
    })?;
    let mut raw = [0; std::mem::size_of::<u32>()];
    raw.copy_from_slice(word);
    Ok(u32::from_ne_bytes(raw))
}

#[cube(launch_unchecked)]
fn block_count_pack(
    codes: &Array<u32>,
    layers: &mut Array<u32>,
    block_zeros: &mut Array<u32>,
    params: &Array<u32>,
    #[comptime] block_size: u32,
) {
    let block = ABSOLUTE_POS as u32;
    let num_blocks = params[3];
    if block < num_blocks {
        let len = params[0];
        let shift = params[1];
        let layer_word_offset = params[2];
        let block_size = u32::cast_from(block_size);
        let start = block * block_size;
        let remaining = len - start;
        let span = if remaining < block_size {
            remaining
        } else {
            block_size
        };
        let end = start + span;
        let word_base = start / 32u32;
        let mut zeros = u32::cast_from(0u32);
        let mut word = u32::cast_from(0u32);
        let mut word_bit = u32::cast_from(0u32);
        let mut word_index = u32::cast_from(0u32);
        let mut position = start;
        while position < end {
            let bit = (codes[position as usize] >> shift) & 1u32;
            zeros += 1u32 - bit;
            word |= bit << word_bit;
            word_bit += 1u32;
            if word_bit == 32u32 {
                layers[(layer_word_offset + word_base + word_index) as usize] = word;
                word = u32::cast_from(0u32);
                word_bit = u32::cast_from(0u32);
                word_index += 1u32;
            }
            position += 1u32;
        }
        if word_bit > 0u32 {
            layers[(layer_word_offset + word_base + word_index) as usize] = word;
        }
        block_zeros[block as usize] = zeros;
    }
}

/// This vector has `ceil(len / 256)` entries. Keeping its sequential scan on
/// the device avoids one readback and upload per wavelet level. A hierarchical
/// scan can replace it later without changing the core backend contract.
#[cube(launch_unchecked)]
fn scan_block_zeros(
    block_zeros: &Array<u32>,
    block_zero_offsets: &mut Array<u32>,
    total_zeros: &mut Array<u32>,
) {
    if ABSOLUTE_POS == 0 {
        let mut total = u32::cast_from(0u32);
        let mut block = u32::cast_from(0u32);
        let block_count = u32::cast_from(block_zeros.len());
        while block < block_count {
            block_zero_offsets[block as usize] = total;
            total += block_zeros[block as usize];
            block += 1u32;
        }
        total_zeros[0] = total;
    }
}

#[cube(launch_unchecked)]
fn stable_scatter(
    codes: &Array<u32>,
    output: &mut Array<u32>,
    block_zero_offsets: &Array<u32>,
    total_zeros: &Array<u32>,
    params: &Array<u32>,
    #[comptime] block_size: u32,
) {
    let block = ABSOLUTE_POS as u32;
    let num_blocks = params[3];
    if block < num_blocks {
        let len = params[0];
        let shift = params[1];
        let total_zeros = total_zeros[0];
        let block_size = u32::cast_from(block_size);
        let start = block * block_size;
        let remaining = len - start;
        let span = if remaining < block_size {
            remaining
        } else {
            block_size
        };
        let end = start + span;
        let zero_base = block_zero_offsets[block as usize];
        let one_base = total_zeros + (start - zero_base);
        let mut local_zero = u32::cast_from(0u32);
        let mut local_one = u32::cast_from(0u32);
        let mut position = start;
        while position < end {
            let code = codes[position as usize];
            let bit = (code >> shift) & 1u32;
            if bit == 0u32 {
                output[(zero_base + local_zero) as usize] = code;
                local_zero += 1u32;
            } else {
                output[(one_base + local_one) as usize] = code;
                local_one += 1u32;
            }
            position += 1u32;
        }
    }
}

/// Reusable CubeCL wavelet-freeze backend.
///
/// Construct it once and reuse it across LSM compactions so CubeCL's runtime,
/// shader cache, and allocator survive between merges. Each rotation performs
/// one upload, keeps all stable partitions device-resident, explicitly
/// synchronizes queued work, and then performs one final readback.
///
/// Device and geometry failures are returned to the caller. Allocation
/// failure, runtime panic, abort, and OOM are not converted into
/// `GpuFreezeError`.
pub struct CubeClWaveletFreeze<R: Runtime> {
    client: ComputeClient<R>,
}

impl<R: Runtime> Default for CubeClWaveletFreeze<R>
where
    R::Device: Default,
{
    fn default() -> Self {
        Self::new(&R::Device::default())
    }
}

impl<R: Runtime> CubeClWaveletFreeze<R> {
    /// Use `device` for all subsequent freeze passes.
    pub fn new(device: &R::Device) -> Self {
        Self {
            client: R::client(device),
        }
    }

    fn freeze_with_alphabet(
        &self,
        alphabet_size: usize,
        sequence: &[u32],
        planes: &mut [&mut [u64]],
        plane_words: &[usize],
    ) -> Result<(), GpuFreezeError> {
        let geometry = FreezeGeometry::checked(alphabet_size, sequence.len(), plane_words)?;
        if let Some((position, &code)) = sequence
            .iter()
            .enumerate()
            .find(|(_, code)| **code as usize >= alphabet_size)
        {
            return Err(GpuFreezeError::CodeOutOfAlphabet {
                position,
                code,
                alphabet_size,
            });
        }
        if sequence.is_empty() {
            for plane in planes {
                plane.fill(0);
            }
            return Ok(());
        }

        let mut current = self.client.create_from_slice(u32::as_bytes(sequence));
        let sequence_bytes = sequence
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or(GpuFreezeError::GeometryOverflow("sequence byte count"))?;
        let mut other = self.client.empty(sequence_bytes);
        let layers = self.client.empty(geometry.packed_bytes);
        let block_bytes = geometry.num_blocks as usize * std::mem::size_of::<u32>();
        let cube_dim = CubeDim::new_1d(THREADS);
        let dispatch = cubecl::calculate_cube_count_elemwise(
            &self.client,
            geometry.num_blocks as usize,
            cube_dim,
        );

        for layer in 0..geometry.width {
            let shift = geometry.width - 1 - layer;
            let layer_word_offset = layer
                .checked_mul(geometry.words_per_layer)
                .ok_or(GpuFreezeError::GeometryOverflow("layer word offset"))?;
            let block_zeros = self.client.empty(block_bytes);
            let count_params = [geometry.len, shift, layer_word_offset, geometry.num_blocks];
            let count_params_handle = self.client.create_from_slice(u32::as_bytes(&count_params));
            unsafe {
                block_count_pack::launch_unchecked::<R>(
                    &self.client,
                    dispatch.clone(),
                    cube_dim,
                    ArrayArg::from_raw_parts(current.clone(), geometry.len as usize),
                    ArrayArg::from_raw_parts(layers.clone(), geometry.packed_words as usize),
                    ArrayArg::from_raw_parts(block_zeros.clone(), geometry.num_blocks as usize),
                    ArrayArg::from_raw_parts(count_params_handle, count_params.len()),
                    BLOCK_SIZE,
                )
            };

            // The final plane is already packed above. Stable partitioning is
            // only needed to order the sequence consumed by the next plane.
            if layer + 1 == geometry.width {
                continue;
            }

            let zero_offsets = self.client.empty(block_bytes);
            let total_zeros = self.client.empty(std::mem::size_of::<u32>());
            unsafe {
                scan_block_zeros::launch_unchecked::<R>(
                    &self.client,
                    CubeCount::Static(1, 1, 1),
                    CubeDim::new_1d(1),
                    ArrayArg::from_raw_parts(block_zeros, geometry.num_blocks as usize),
                    ArrayArg::from_raw_parts(zero_offsets.clone(), geometry.num_blocks as usize),
                    ArrayArg::from_raw_parts(total_zeros.clone(), 1),
                )
            };
            let scatter_params = [geometry.len, shift, 0u32, geometry.num_blocks];
            let scatter_params_handle = self
                .client
                .create_from_slice(u32::as_bytes(&scatter_params));
            unsafe {
                stable_scatter::launch_unchecked::<R>(
                    &self.client,
                    dispatch.clone(),
                    cube_dim,
                    ArrayArg::from_raw_parts(current.clone(), geometry.len as usize),
                    ArrayArg::from_raw_parts(other.clone(), geometry.len as usize),
                    ArrayArg::from_raw_parts(zero_offsets, geometry.num_blocks as usize),
                    ArrayArg::from_raw_parts(total_zeros, 1),
                    ArrayArg::from_raw_parts(scatter_params_handle, scatter_params.len()),
                    BLOCK_SIZE,
                )
            };
            std::mem::swap(&mut current, &mut other);
        }

        cubecl::future::block_on(self.client.sync())
            .map_err(|error| GpuFreezeError::Device(format!("{error:?}")))?;
        let packed_bytes = self
            .client
            .read_one(layers)
            .map_err(|error| GpuFreezeError::Device(format!("{error:?}")))?;
        if packed_bytes.len() != geometry.packed_bytes {
            return Err(GpuFreezeError::ReadbackSize {
                expected: geometry.packed_bytes,
                actual: packed_bytes.len(),
            });
        }
        for (depth, output) in planes.iter_mut().enumerate() {
            output.fill(0);
            let base = depth
                .checked_mul(geometry.words_per_layer as usize)
                .ok_or(GpuFreezeError::GeometryOverflow("host layer word offset"))?;
            for (word, slot) in output.iter_mut().enumerate() {
                let low_index = base
                    .checked_add(word * 2)
                    .ok_or(GpuFreezeError::GeometryOverflow("host packed word index"))?;
                let high_in_layer = word * 2 + 1;
                let low = read_packed_u32(&packed_bytes, low_index)? as u64;
                let high = if high_in_layer < geometry.words_per_layer as usize {
                    read_packed_u32(&packed_bytes, base + high_in_layer)? as u64
                } else {
                    0
                };
                *slot = low | (high << 32);
            }
        }
        Ok(())
    }
}

impl<R: Runtime> WaveletMatrixFreezeBackend for CubeClWaveletFreeze<R> {
    type Error = GpuFreezeError;

    fn freeze_rotation(
        &self,
        _rotation: SuccinctRotation,
        alphabet_size: usize,
        sequence: &[u32],
        planes: &mut [&mut [u64]],
    ) -> Result<(), Self::Error> {
        let plane_words: Vec<_> = planes.iter().map(|plane| plane.len()).collect();
        self.freeze_with_alphabet(alphabet_size, sequence, planes, &plane_words)
    }
}

/// WGPU/Metal/Vulkan backend using CubeCL's selected device.
#[cfg(feature = "wgpu")]
pub type WgpuWaveletFreeze = CubeClWaveletFreeze<cubecl::wgpu::WgpuRuntime>;

/// CUDA backend using CubeCL's selected device.
#[cfg(feature = "cuda")]
pub type CudaWaveletFreeze = CubeClWaveletFreeze<cubecl::cuda::CudaRuntime>;
