// SPDX-License-Identifier: MPL-2.0

use std::fs;

use crate::util;

#[test]
fn cached_elf_with_invalid_alternatives_cannot_be_packaged_or_run() {
    let directory = tempfile::tempdir().unwrap();
    util::cargo_osdk(["new", "--kernel", "altcheck"])
        .current_dir(directory.path())
        .ok()
        .unwrap();
    let kernel = directory.path().join("altcheck");
    util::edit_config_files(&kernel);
    let args = ["build", "--release"];
    let output = util::cargo_osdk(args)
        .current_dir(&kernel)
        .env("OSDK_LOG_LEVEL", "info")
        .ok()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("Validated 0 x86 alternatives"));

    let reused = util::cargo_osdk(args)
        .current_dir(&kernel)
        .env("OSDK_LOG_LEVEL", "info")
        .ok()
        .unwrap();
    let stderr = String::from_utf8_lossy(&reused.stderr);
    assert!(stderr.contains("Validated 0 x86 alternatives"), "{stderr}");
    assert!(stderr.contains("Reusing existing bundle"), "{stderr}");

    let elf_path = kernel.join("target/x86_64-unknown-none/release/altcheck-osdk-bin");
    let mut bytes = fs::read(&elf_path).unwrap();
    let elf = xmas_elf::ElfFile::new(&bytes).unwrap();
    let registry = elf.find_section_by_name(".altgroups").unwrap();
    let offset = registry.offset() as usize;
    bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&elf_path, bytes).unwrap();

    // Cargo's output exists and the bundle has already been packaged. Both
    // commands must recheck the ELF before considering that cached bundle.
    for command in ["build", "run"] {
        let output = util::cargo_osdk([command, "--release"])
            .current_dir(&kernel)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(7));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Invalid x86 alternatives"), "{stderr}");
        assert!(stderr.contains("unsupported .altgroups format"), "{stderr}");
    }
}
