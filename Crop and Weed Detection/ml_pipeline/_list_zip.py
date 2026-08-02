import zipfile
p = r"C:\Users\Palavalasa Kusuma\Downloads\Project5_Ag_Crop and weed detection.zip"
with zipfile.ZipFile(p) as z:
    matches = [n for n in z.namelist() if n.lower().endswith(('.jpg','.jpeg','.png','.txt'))]
    for i,n in enumerate(matches[:500]):
        print(n)
    print('---', len(matches))
