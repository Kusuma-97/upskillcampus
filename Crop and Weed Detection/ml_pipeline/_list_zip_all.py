import zipfile
p = r"C:\Users\Palavalasa Kusuma\Downloads\Project5_Ag_Crop and weed detection.zip"
with zipfile.ZipFile(p) as z:
    names = z.namelist()
    for i,n in enumerate(names[:500]):
        print(n)
    print('--- total entries:', len(names))
