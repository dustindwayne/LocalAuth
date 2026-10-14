use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=assets/localauth.ico");
    println!("cargo:rerun-if-changed=assets/localauth.rc");
    println!("cargo:rerun-if-env-changed=RC");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let compiler = env::var_os("RC").map(PathBuf::from).unwrap_or_else(|| {
            let kits = PathBuf::from(
                env::var_os("ProgramFiles(x86)")
                    .unwrap_or_else(|| "C:\\Program Files (x86)".into()),
            )
            .join("Windows Kits/10/bin");
            let mut candidates: Vec<_> = fs::read_dir(kits)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|entry| entry.path().join("x64/rc.exe"))
                .filter(|path| path.is_file())
                .collect();
            candidates.sort();
            candidates.pop().unwrap_or_else(|| PathBuf::from("rc.exe"))
        });
        let resource = output.join("localauth.res");
        let status = Command::new(compiler)
            .arg("/nologo")
            .arg("/fo")
            .arg(&resource)
            .arg("assets/localauth.rc")
            .status()
            .expect("Windows SDK resource compiler required; set RC if needed");
        assert!(status.success(), "Windows icon resource compilation failed");
        println!(
            "cargo:rustc-link-arg-bin=localauth-home={}",
            resource.display()
        );
    } else {
        let resource = output.join("localauth-icon.o");
        let status = Command::new(env::var_os("RC").unwrap_or_else(|| "windres".into()))
            .args(["assets/localauth.rc", "-O", "coff", "-o"])
            .arg(&resource)
            .status()
            .expect("MinGW resource compiler required; set RC if needed");
        assert!(status.success(), "Windows icon resource compilation failed");
        println!(
            "cargo:rustc-link-arg-bin=localauth-home={}",
            resource.display()
        );
    }
}
