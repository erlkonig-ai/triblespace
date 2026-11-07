use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use quote::ToTokens;

use syn::parse::Parse;
use syn::parse::ParseStream;
use syn::FnArg;
use syn::ItemFn;
use syn::ReturnType;
use syn::Token;
use syn::Type;
use syn::TypeParamBound;
use syn::Visibility;

const WASM_OUTPUT_BYTES: usize = 8 * 1024;
const WASM_STACK_SIZE_BYTES: usize = 128 * 1024;
const WASM_INITIAL_MEMORY_BYTES: usize = 8 * 64 * 1024;
const WASM_MAX_MEMORY_BYTES: usize = 8 * 64 * 1024;

pub fn value_formatter_impl(attr: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let args: ValueFormatterArgs = syn::parse2(attr)?;
    let mut item_fn: ItemFn = syn::parse2(item)?;
    validate_signature(&item_fn)?;
    item_fn.attrs.push(syn::parse_quote!(#[allow(dead_code)]));

    let wasm_path = compile_wasm_formatter(&item_fn)?;
    let wasm_path = wasm_path.to_string_lossy();
    let wasm_path = syn::LitStr::new(wasm_path.as_ref(), Span::call_site());

    let (const_vis, const_ident) = args.const_spec(&item_fn);

    Ok(quote! {
        #item_fn

        #const_vis const #const_ident: &[u8] = include_bytes!(#wasm_path);
    })
}

#[derive(Default)]
struct ValueFormatterArgs {
    const_wasm: Option<syn::Ident>,
    vis: Option<Visibility>,
}

impl Parse for ValueFormatterArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut out = ValueFormatterArgs::default();

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            if key == "const_wasm" {
                input.parse::<Token![=]>()?;
                let name: syn::Ident = input.parse()?;
                if out.const_wasm.replace(name).is_some() {
                    return Err(syn::Error::new_spanned(
                        key,
                        "`const_wasm` can only be specified once",
                    ));
                }
            } else if key == "vis" {
                let content;
                syn::parenthesized!(content in input);
                let vis: Visibility = content.parse()?;
                if !content.is_empty() {
                    return Err(syn::Error::new_spanned(
                        key,
                        "`vis(...)` must contain only a Rust visibility (e.g. `vis(pub(crate))`)",
                    ));
                }
                if out.vis.replace(vis).is_some() {
                    return Err(syn::Error::new_spanned(
                        key,
                        "`vis(...)` can only be specified once",
                    ));
                }
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "unknown argument; expected `const_wasm = NAME` and/or `vis(...)`",
                ));
            }

            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        Ok(out)
    }
}

impl ValueFormatterArgs {
    fn const_spec(&self, item_fn: &ItemFn) -> (Visibility, syn::Ident) {
        let vis = self.vis.clone().unwrap_or_else(|| item_fn.vis.clone());
        let name = match &self.const_wasm {
            Some(name) => name.clone(),
            None => {
                let const_name = format!("{}_WASM", item_fn.sig.ident.to_string().to_uppercase());
                format_ident!("{const_name}")
            }
        };
        (vis, name)
    }
}

fn validate_signature(item_fn: &ItemFn) -> syn::Result<()> {
    if item_fn.sig.asyncness.is_some() {
        return Err(syn::Error::new_spanned(
            item_fn.sig.asyncness,
            "`#[value_formatter]` does not support async functions",
        ));
    }

    if !item_fn.sig.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item_fn.sig.generics,
            "`#[value_formatter]` does not support generics",
        ));
    }

    if item_fn.sig.inputs.len() != 2 {
        return Err(syn::Error::new_spanned(
            &item_fn.sig.inputs,
            "`#[value_formatter]` expects `fn(raw: &[u8; 32], out: &mut impl core::fmt::Write) -> Result<(), u32>`",
        ));
    }

    validate_raw_arg(item_fn.sig.inputs.first().expect("len checked"))?;
    validate_out_arg(item_fn.sig.inputs.iter().nth(1).expect("len checked"))?;
    validate_return_type(&item_fn.sig.output)?;

    Ok(())
}

fn validate_raw_arg(arg: &FnArg) -> syn::Result<()> {
    let FnArg::Typed(pat) = arg else {
        return Err(syn::Error::new_spanned(
            arg,
            "`#[value_formatter]` does not support methods",
        ));
    };

    let Type::Reference(ty) = pat.ty.as_ref() else {
        return Err(syn::Error::new_spanned(
            &pat.ty,
            "first argument must be `&[u8; 32]`",
        ));
    };

    let Type::Array(arr) = ty.elem.as_ref() else {
        return Err(syn::Error::new_spanned(
            &ty.elem,
            "first argument must be `&[u8; 32]`",
        ));
    };

    match (arr.elem.as_ref(), &arr.len) {
        (Type::Path(elem), syn::Expr::Lit(expr)) => {
            if !path_ends_with(&elem.path, "u8") {
                return Err(syn::Error::new_spanned(
                    &arr.elem,
                    "first argument must be `&[u8; 32]`",
                ));
            }

            let syn::Lit::Int(len) = &expr.lit else {
                return Err(syn::Error::new_spanned(
                    &arr.len,
                    "first argument must be `&[u8; 32]`",
                ));
            };

            if len.base10_parse::<usize>().ok() != Some(32) {
                return Err(syn::Error::new_spanned(
                    &arr.len,
                    "first argument must be `&[u8; 32]`",
                ));
            }
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &arr.len,
                "first argument must be `&[u8; 32]`",
            ));
        }
    }

    Ok(())
}

fn validate_out_arg(arg: &FnArg) -> syn::Result<()> {
    let FnArg::Typed(pat) = arg else {
        return Err(syn::Error::new_spanned(
            arg,
            "`#[value_formatter]` does not support methods",
        ));
    };

    let Type::Reference(ty) = pat.ty.as_ref() else {
        return Err(syn::Error::new_spanned(
            &pat.ty,
            "second argument must be `&mut impl core::fmt::Write` or `&mut dyn core::fmt::Write`",
        ));
    };

    if ty.mutability.is_none() {
        return Err(syn::Error::new_spanned(
            &pat.ty,
            "second argument must be mutable (`&mut ...`)",
        ));
    }

    let bounds = match ty.elem.as_ref() {
        Type::TraitObject(obj) => Some(&obj.bounds),
        Type::ImplTrait(imp) => Some(&imp.bounds),
        _ => None,
    };

    let Some(bounds) = bounds else {
        return Err(syn::Error::new_spanned(
            &ty.elem,
            "second argument must be `&mut impl core::fmt::Write` or `&mut dyn core::fmt::Write`",
        ));
    };

    let includes_write = bounds.iter().any(|bound| match bound {
        TypeParamBound::Trait(tr) => path_ends_with(&tr.path, "Write"),
        _ => false,
    });

    if !includes_write {
        return Err(syn::Error::new_spanned(
            bounds,
            "second argument must include the `core::fmt::Write` trait",
        ));
    }

    Ok(())
}

fn validate_return_type(output: &ReturnType) -> syn::Result<()> {
    let ReturnType::Type(_, ty) = output else {
        return Err(syn::Error::new_spanned(
            output,
            "return type must be `Result<(), u32>`",
        ));
    };

    let Type::Path(path) = ty.as_ref() else {
        return Err(syn::Error::new_spanned(
            ty,
            "return type must be `Result<(), u32>`",
        ));
    };

    let Some(seg) = path.path.segments.last() else {
        return Err(syn::Error::new_spanned(
            ty,
            "return type must be `Result<(), u32>`",
        ));
    };

    if seg.ident != "Result" {
        return Err(syn::Error::new_spanned(
            ty,
            "return type must be `Result<(), u32>`",
        ));
    }

    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Err(syn::Error::new_spanned(
            &seg.arguments,
            "return type must be `Result<(), u32>`",
        ));
    };

    let mut types = args.args.iter().filter_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    });

    let Some(ok_ty) = types.next() else {
        return Err(syn::Error::new_spanned(
            args,
            "return type must be `Result<(), u32>`",
        ));
    };

    if !matches!(ok_ty, Type::Tuple(tuple) if tuple.elems.is_empty()) {
        return Err(syn::Error::new_spanned(
            ok_ty,
            "return type must be `Result<(), u32>`",
        ));
    }

    let Some(err_ty) = types.next() else {
        return Err(syn::Error::new_spanned(
            args,
            "return type must be `Result<(), u32>`",
        ));
    };

    let Type::Path(err_path) = err_ty else {
        return Err(syn::Error::new_spanned(
            err_ty,
            "return type must be `Result<(), u32>`",
        ));
    };

    if !path_ends_with(&err_path.path, "u32") {
        return Err(syn::Error::new_spanned(
            err_ty,
            "return type must be `Result<(), u32>`",
        ));
    }

    Ok(())
}

fn path_ends_with(path: &syn::Path, ident: &str) -> bool {
    path.segments
        .last()
        .map(|seg| seg.ident == ident)
        .unwrap_or(false)
}

fn compile_wasm_formatter(item_fn: &ItemFn) -> syn::Result<PathBuf> {
    let out_dir = target_dir()?.join("value_formatter");
    compile_wasm_formatter_in(item_fn, &out_dir)
}

fn compile_wasm_formatter_in(item_fn: &ItemFn, out_dir: &Path) -> syn::Result<PathBuf> {
    let stem = format!("{}_{}", item_fn.sig.ident, formatter_hash(item_fn));
    cache_wasm_formatter(out_dir, &stem, |src_path, wasm_path| {
        compile_wasm_source(item_fn, src_path, wasm_path, out_dir)
    })
}

fn compile_wasm_source(
    item_fn: &ItemFn,
    src_path: &Path,
    wasm_path: &Path,
    out_dir: &Path,
) -> syn::Result<()> {
    let source = wasm_crate_source(item_fn);
    std::fs::write(src_path, source).map_err(|err| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to write wasm source: {err}"),
        )
    })?;

    // Keep file!(), diagnostics and embedded source paths independent of the
    // private build directory. The basename also preserves the old crate name.
    let mut remap = src_path
        .parent()
        .expect("formatter source has a parent")
        .as_os_str()
        .to_os_string();
    remap.push("=");
    remap.push(out_dir);
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg("--crate-type=cdylib")
        .arg("--crate-name")
        .arg(src_path.file_stem().expect("formatter source has a stem"))
        .arg("--remap-path-prefix")
        .arg(remap)
        .arg("--target=wasm32-unknown-unknown")
        .arg("--edition=2021")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("opt-level=z")
        .arg("-C")
        .arg("strip=symbols")
        .arg("-C")
        .arg("link-arg=-z")
        .arg("-C")
        .arg(format!("link-arg=stack-size={WASM_STACK_SIZE_BYTES}"))
        .arg("-C")
        .arg("link-arg=--export-memory")
        .arg("-C")
        .arg(format!(
            "link-arg=--initial-memory={WASM_INITIAL_MEMORY_BYTES}"
        ))
        .arg("-C")
        .arg(format!("link-arg=--max-memory={WASM_MAX_MEMORY_BYTES}"))
        .arg("-o")
        .arg(wasm_path)
        .arg(src_path)
        .output()
        .map_err(|err| {
            syn::Error::new(
                Span::call_site(),
                format!("failed to run rustc for wasm formatter: {err}"),
            )
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(syn::Error::new(
            item_fn.sig.ident.span(),
            format!(
                "failed to compile wasm formatter (install `wasm32-unknown-unknown` with `rustup target add wasm32-unknown-unknown`)\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}",
            ),
        ));
    }
    Ok(())
}

// A completed artifact is published once. In particular, rename() would let a
// losing compiler replace the winner and invalidate Cargo's include_bytes!
// dependency timestamp. The private directory is on the same filesystem so a
// hard link provides atomic publication without overwriting an existing name.
fn cache_wasm_formatter(
    out_dir: &Path,
    stem: &str,
    compile: impl FnOnce(&Path, &Path) -> syn::Result<()>,
) -> syn::Result<PathBuf> {
    let io_error = |err| syn::Error::new(Span::call_site(), format!("wasm formatter cache: {err}"));
    std::fs::create_dir_all(out_dir).map_err(io_error)?;
    let wasm_path = out_dir.join(format!("{stem}.wasm"));
    if cached_file_exists(&wasm_path).map_err(io_error)? {
        return Ok(wasm_path);
    }

    let build = FormatterBuildDir::new(out_dir).map_err(io_error)?;
    let src_path = build.0.join(format!("{stem}.rs"));
    let built_wasm = build.0.join(format!("{stem}.wasm"));
    compile(&src_path, &built_wasm)?;
    match std::fs::hard_link(&built_wasm, &wasm_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            // Only another regular cache file is a winner. Do not follow a
            // symlink (including a dangling one) or hide other I/O failures.
            if !cached_file_exists(&wasm_path).map_err(io_error)? {
                return Err(io_error(err));
            }
        }
        Err(err) => return Err(io_error(err)),
    }
    Ok(wasm_path)
}

fn cached_file_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

struct FormatterBuildDir(PathBuf);

impl FormatterBuildDir {
    fn new(parent: &Path) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".build-{}-{sequence}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                // A crashed process can leave a directory behind. Never reuse
                // it or wait for it: it owns no cache name and is not a lock.
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

impl Drop for FormatterBuildDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn formatter_hash(item_fn: &ItemFn) -> String {
    let tokens = item_fn.to_token_stream().to_string();
    let mut hasher = DefaultHasher::new();
    tokens.hash(&mut hasher);
    format!("{:016X}", hasher.finish())
}

fn target_dir() -> syn::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(dir));
    }

    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "`#[value_formatter]` requires `CARGO_MANIFEST_DIR` to be set",
        )
    })?;
    let manifest_dir = PathBuf::from(manifest_dir);

    let workspace_root = workspace_root(&manifest_dir).unwrap_or_else(|| manifest_dir.clone());
    Ok(workspace_root.join("target"))
}

fn workspace_root(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        let Ok(contents) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        if contents.contains("[workspace]") {
            return Some(dir.to_path_buf());
        }
    }
    None
}

fn wasm_crate_source(item_fn: &ItemFn) -> String {
    let fn_ident = &item_fn.sig.ident;
    let fn_item = item_fn.to_token_stream();
    let output_cap = WASM_OUTPUT_BYTES;

    let tokens = quote! {
        #![no_std]

        use core::fmt::Write;

        const OUTPUT_CAP: usize = #output_cap;

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
            loop {}
        }

        struct FormatterOut {
            ptr: *mut u8,
            len: usize,
            cap: usize,
        }

        impl FormatterOut {
            unsafe fn new(ptr: *mut u8, cap: usize) -> Self {
                Self { ptr, len: 0, cap }
            }

            fn len(&self) -> usize {
                self.len
            }
        }

        impl Write for FormatterOut {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                if self.len.saturating_add(bytes.len()) > self.cap {
                    return Err(core::fmt::Error);
                }

                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.len), bytes.len());
                }
                self.len += bytes.len();
                Ok(())
            }
        }

        static mut OUTPUT: [u8; OUTPUT_CAP + 1] = [0; OUTPUT_CAP + 1];

        #fn_item

        #[no_mangle]
        pub extern "C" fn format(w0: i64, w1: i64, w2: i64, w3: i64) -> i64 {
            let mut raw = [0u8; 32];
            raw[0..8].copy_from_slice(&w0.to_le_bytes());
            raw[8..16].copy_from_slice(&w1.to_le_bytes());
            raw[16..24].copy_from_slice(&w2.to_le_bytes());
            raw[24..32].copy_from_slice(&w3.to_le_bytes());

            let ptr = unsafe { core::ptr::addr_of_mut!(OUTPUT).cast::<u8>().add(1) };
            let mut out = unsafe { FormatterOut::new(ptr, OUTPUT_CAP) };

            match #fn_ident(&raw, &mut out) {
                Ok(()) => {
                    let len = out.len() as u64;
                    let ptr = (ptr as u32) as u64;
                    let packed = (len << 32) | ptr;
                    packed as i64
                }
                Err(code) => {
                    let packed = (code as u64) << 32;
                    packed as i64
                }
            }
        }
    };

    tokens.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, SystemTime};

    fn test_dir() -> FormatterBuildDir {
        FormatterBuildDir::new(&std::env::temp_dir()).unwrap()
    }

    fn entries(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn slow_and_failed_compilers_cannot_expose_partial_or_replace_winner() {
        let dir = test_dir();
        let final_path = dir.0.join("formatter.wasm");
        thread::scope(|scope| {
            let mut writers = Vec::new();
            for fails in [false, true] {
                let (started_tx, started_rx) = mpsc::channel();
                let (finish_tx, finish_rx) = mpsc::channel();
                let cache = &dir.0;
                let writer = scope.spawn(move || {
                    cache_wasm_formatter(cache, "formatter", |source, output| {
                        fs::write(source, "private source").unwrap();
                        fs::write(output, "partial").unwrap();
                        started_tx.send(output.to_path_buf()).unwrap();
                        finish_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                        if fails {
                            return Err(syn::Error::new(Span::call_site(), "compiler failed"));
                        }
                        fs::write(output, "complete loser").unwrap();
                        Ok(())
                    })
                    .map_err(|error| error.to_string())
                });
                let private_output = started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                assert_eq!(fs::read(&private_output).unwrap(), b"partial");
                assert!(!final_path.exists());
                writers.push((fails, private_output, finish_tx, writer));
            }
            assert_ne!(writers[0].1, writers[1].1);
            let winner = cache_wasm_formatter(&dir.0, "formatter", |source, output| {
                fs::write(source, "winning source").unwrap();
                fs::write(output, "complete winner").unwrap();
                Ok(())
            })
            .unwrap();
            // A fixed old time detects replacement even on coarse filesystems.
            let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(123456);
            fs::File::options()
                .write(true)
                .open(&winner)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(timestamp))
                .unwrap();
            let modified = fs::metadata(&winner).unwrap().modified().unwrap();
            for (fails, private_output, finish_tx, writer) in writers {
                finish_tx.send(()).unwrap();
                let result = writer.join().unwrap();
                if fails {
                    assert_eq!(result.unwrap_err(), "compiler failed");
                } else {
                    assert_eq!(result.unwrap(), winner);
                }
                assert!(!private_output.parent().unwrap().exists());
                assert_eq!(fs::read(&winner).unwrap(), b"complete winner");
                assert_eq!(fs::metadata(&winner).unwrap().modified().unwrap(), modified);
            }
            assert_eq!(entries(&dir.0), 1);
            assert_eq!(
                cache_wasm_formatter(&dir.0, "formatter", |_, _| {
                    panic!("cache hit must not compile")
                })
                .unwrap(),
                winner
            );
        });
    }

    #[test]
    fn simultaneous_publishers_return_one_complete_artifact() {
        let dir = test_dir();
        let barrier = Arc::new(Barrier::new(8));
        thread::scope(|scope| {
            let handles: Vec<_> = (0u8..8)
                .map(|byte| {
                    let barrier = barrier.clone();
                    let cache = &dir.0;
                    scope.spawn(move || {
                        cache_wasm_formatter(cache, "formatter", |source, output| {
                            fs::write(source, [byte]).unwrap();
                            fs::write(output, vec![byte; 65536]).unwrap();
                            barrier.wait();
                            Ok(())
                        })
                        .unwrap()
                    })
                })
                .collect();
            for handle in handles {
                let path = handle.join().unwrap();
                let bytes = fs::read(path).unwrap();
                assert_eq!(bytes.len(), 65536);
                assert!(bytes[0] < 8);
                assert!(bytes.iter().all(|byte| *byte == bytes[0]));
            }
        });
        assert_eq!(entries(&dir.0), 1);
    }

    #[test]
    fn compiler_and_publication_failures_remove_private_files() {
        let dir = test_dir();
        let error = cache_wasm_formatter(&dir.0, "formatter", |source, output| {
            fs::write(source, "invalid source").unwrap();
            fs::write(output, "partial").unwrap();
            Err(syn::Error::new(Span::call_site(), "compiler failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "compiler failed");
        assert_eq!(entries(&dir.0), 0);
        // A successful compiler that did not produce an output is also an error.
        assert!(cache_wasm_formatter(&dir.0, "formatter", |_, _| Ok(())).is_err());
        assert_eq!(entries(&dir.0), 0);
        let final_path = dir.0.join("formatter.wasm");
        assert!(cache_wasm_formatter(&dir.0, "formatter", |_, output| {
            fs::write(output, "complete").unwrap();
            fs::create_dir(&final_path).unwrap();
            Ok(())
        })
        .is_err());
        assert!(final_path.is_dir());
        assert_eq!(entries(&dir.0), 1);
    }

    #[test]
    fn cache_file_errors_are_not_misses() {
        let dir = test_dir();
        fs::create_dir(dir.0.join("formatter.wasm")).unwrap();
        let error = cache_wasm_formatter(&dir.0, "formatter", |_, _| {
            panic!("invalid cache entry must not be compiled over")
        })
        .unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
        let parent_file = dir.0.join("file");
        fs::write(&parent_file, "not a directory").unwrap();
        assert!(cache_wasm_formatter(&parent_file, "formatter", |_, _| {
            panic!("I/O error must not be treated as a miss")
        })
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_symlinks_are_not_winners() {
        let dir = test_dir();
        let target = dir.0.join("target");
        let link = dir.0.join("formatter.wasm");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        for exists in [false, true] {
            if exists {
                fs::write(&target, "untouched").unwrap();
            }
            assert!(cache_wasm_formatter(&dir.0, "formatter", |_, _| {
                panic!("symlink must not be a cache hit")
            })
            .is_err());
        }
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
    }

    #[test]
    #[ignore = "requires rustc with the wasm32-unknown-unknown target"]
    fn real_wasm_compile_preserves_source_identity_and_cleans_failures() {
        let dir = test_dir();
        let item: ItemFn = syn::parse_quote! {
            fn formatter(_: &[u8; 32], out: &mut impl core::fmt::Write) -> Result<(), u32> {
                write!(out, "{}:{}", file!(), module_path!()).map_err(|_| 1)
            }
        };
        let stem = format!("{}_{}", item.sig.ident, formatter_hash(&item));
        let direct_source = dir.0.join(format!("{stem}.rs"));
        let direct_output = dir.0.join("direct.wasm");
        compile_wasm_source(&item, &direct_source, &direct_output, &dir.0).unwrap();
        let expected = fs::read(&direct_output).unwrap();
        assert!(expected.starts_with(b"\0asm"));
        let source_name = direct_source.to_string_lossy();
        assert!(expected
            .windows(source_name.len())
            .any(|bytes| bytes == source_name.as_bytes()));
        fs::remove_file(direct_source).unwrap();
        fs::remove_file(direct_output).unwrap();
        // Force two real compiler invocations into the publication race.
        let barrier = Barrier::new(2);
        thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let cache = &dir.0;
                    let stem = &stem;
                    let barrier = &barrier;
                    let tokens = item.to_token_stream().to_string();
                    scope.spawn(move || {
                        let item = syn::parse_str(&tokens).unwrap();
                        cache_wasm_formatter(cache, stem, |source, output| {
                            let result = compile_wasm_source(&item, source, output, cache);
                            barrier.wait();
                            result
                        })
                        .unwrap()
                    })
                })
                .collect();
            for handle in handles {
                assert_eq!(fs::read(handle.join().unwrap()).unwrap(), expected);
            }
        });
        assert_eq!(entries(&dir.0), 1);
        let invalid: ItemFn = syn::parse_quote! {
            fn invalid(_: &[u8; 32], _: &mut impl core::fmt::Write) -> Result<(), u32> {
                missing_function()
            }
        };
        let error = compile_wasm_formatter_in(&invalid, &dir.0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to compile wasm formatter"));
        assert!(error.contains("missing_function"));
        assert_eq!(entries(&dir.0), 1);
    }
}
