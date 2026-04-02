import os
import re
import shutil
from pathlib import Path

# תיקיות לסריקה (ניתן להוסיף/להסיר)
TARGET_DIRS = ["app", "frontend/src"]
# סיומות קבצים רלוונטיות
EXTENSIONS = {".py", ".jsx", ".js", ".html", ".css", ".json"}

# תבנית לזיהוי תווים עבריים
HEBREW_PATTERN = re.compile(r'[\u0590-\u05FF]')
# תבנית לזיהוי מפתחות עם _hebrew (למשל explanation_hebrew)
HEBREW_KEY_PATTERN = re.compile(r'\b\w+_hebrew\b')

def backup_file(file_path):
    """יצירת עותק גיבוי עם סיומת .bak"""
    backup_path = file_path + ".bak"
    shutil.copy2(file_path, backup_path)
    return backup_path

def remove_hebrew_from_file(file_path):
    """קריאת קובץ, הסרת שורות עם עברית או מפתחות hebrew, שמירה"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {e}")
        return False

    modified = False
    new_lines = []

    for line in lines:
        # אם השורה מכילה תווים עבריים – מחק אותה (או נסה להשאיר חלק?)
        if HEBREW_PATTERN.search(line):
            # אפשר להדפיס את השורה שנמחקת
            print(f"  ✂️ Removing Hebrew line in {file_path}: {line.strip()[:80]}")
            modified = True
            continue

        # אם השורה מכילה מפתח *_hebrew (כמו explanation_hebrew) – מחק אותה
        if HEBREW_KEY_PATTERN.search(line):
            print(f"  ✂️ Removing hebrew key line in {file_path}: {line.strip()[:80]}")
            modified = True
            continue

        # שמור שורות תקינות
        new_lines.append(line)

    if modified:
        backup_file(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
        print(f"✅ Updated: {file_path}")
        return True
    else:
        print(f"⏭️ No Hebrew found in: {file_path}")
        return False

def main():
    base_dir = Path.cwd()
    print(f"Starting removal of Hebrew text in: {base_dir}")
    print("=" * 60)

    total_files = 0
    modified_files = 0

    for target in TARGET_DIRS:
        target_path = base_dir / target
        if not target_path.exists():
            print(f"⚠️ Directory not found: {target_path}")
            continue

        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in EXTENSIONS:
                    total_files += 1
                    if remove_hebrew_from_file(file_path):
                        modified_files += 1

    print("=" * 60)
    print(f"✅ Done. Checked {total_files} files, modified {modified_files} files.")
    print("⚠️ Backups created with .bak extension. Review changes and delete backups when satisfied.")

if __name__ == "__main__":
    main()