def is_line_usefull(line):
    line = line.strip()
    cnt = 0
    while cnt<len(line) and line[cnt]!='#' and line[cnt]!='\n':
        cnt += 1
    return cnt>0

def create_modified_file():
    with open("default.cnf") as default:
        with open("modified.cnf","w") as file_new:
            for line in default:
                file_new.write(line)

def remove_comments():
    with open("modified.cnf","r+") as file:
        lines = file.readlines()
        file.seek(0)
        for line in lines:
            if is_line_usefull(line):
                file.write(line)
        file.truncate()

def replace_providers():
    old = str()
    new = str()
    with open("old-providers.txt","r") as file:
        old = file.read().strip()
    with open("new-providers.txt","r") as file:
        new = file.read().strip()
    with open("modified.cnf","r+") as file:
        content = file.read()
        content = content.replace(old,new)
        file.seek(0)
        file.write(content)
        file.truncate()

create_modified_file()
remove_comments()
replace_providers()