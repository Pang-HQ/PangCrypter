import os
from prompt_toolkit.shortcuts import checkboxlist_dialog

# Directory to scan
root_dir = "./pangcrypter"

# Extensions to include
extensions = {".py"}  # modify as needed

# Collect files and their line counts
file_entries = []
for dirpath, dirnames, filenames in os.walk(root_dir):
    for filename in filenames:
        if any(filename.endswith(ext) for ext in extensions):
            file_path = os.path.join(dirpath, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    line_count = sum(1 for _ in f)
            except Exception:
                line_count = 0  # If file can't be read
            display_text = f"{filename} ({line_count} lines)"
            file_entries.append((file_path, display_text))

# Interactive checkbox dialog
selected_files = checkboxlist_dialog(
    title="Select Files",
    text="Use arrow keys to navigate, space to toggle selection, Enter to finish:",
    values=[(fp, disp) for fp, disp in file_entries]
).run()

# Write selected files to Structure.txt
if selected_files:
    with open("Structure.txt", "w", encoding="utf-8") as out_f:
        for file_path in selected_files:
            out_f.write(f"File: {file_path}\n")
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    contents = f.read()
                out_f.write(contents + "\n")
            except Exception as e:
                out_f.write(f"Could not read file: {e}\n")
            out_f.write("-" * 40 + "\n")
    print("Selected files written to Structure.txt")
else:
    print("No files selected. Exiting.")
