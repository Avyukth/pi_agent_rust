use pi::extensions_js::PiJsRuntime;
use std::fs;
use tempfile::TempDir;

#[test]
fn repro_ext_path_traversal() {
    futures::executor::block_on(async {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let ext_root = root.join("ext");
        fs::create_dir(&ext_root).unwrap();

        let secret_file = root.join("secret.js");
        fs::write(&secret_file, "export const secret = 's3cr3t';").unwrap();

        // index.js inside ext_root tries to import ../secret.js
        let index_file = ext_root.join("index.js");
        fs::write(
            &index_file,
            "import { secret } from '../secret.js'; globalThis.secret = secret;",
        )
        .unwrap();

        let runtime = PiJsRuntime::new().await.unwrap();

        // Register extension root
        runtime.add_extension_root(ext_root.clone());

        // Try to evaluate the module
        let result = runtime.eval_file(&index_file).await;

        // We expect this to FAIL with "Module path escapes extension root"
        match result {
            Ok(()) => panic!("Should have failed to import module outside root, but succeeded!"),
            Err(e) => {
                println!("Got expected error: {e}");
                assert!(
                    e.to_string().contains("Module path escapes extension root"),
                    "Unexpected error message: {e}",
                );
            }
        }
    });
}
