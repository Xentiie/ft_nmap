with open("./res", "r") as f:
	content = f.read()

lst = content.split()
lst = [int(l) for l in lst if l.isdigit()]
lst.sort()
print(lst)

