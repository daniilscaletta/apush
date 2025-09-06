from tkinter import YES
import requests
import sys
from pathlib import Path
import re
import json
from bs4 import BeautifulSoup

#  red_secret_admin
#  red_secret_admin_2033


s = None
Nonce = None


RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"


def set_addr():
    """
    Устанавливает адрес хоста для подключения.
    
    Использование:
        Если аргумент не указан, по умолчанию используется 'bourd.vkactf.ru'
        Можно указать свой хост или ip:port  качестве первого аргумента
        Для вывода справки используйте -h или --help
    
    Примеры:
        python3 script.py example.com      # подключится к http://example.com
        python3 script.py 12.2.3.23:2333   # подключится к http://12.2.3.23:2333
        python3 script.py -h               # выведет справку
    """
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print(YELLOW + set_addr.__doc__ + RESET)
            sys.exit(0)
        else:    
            host = sys.argv[1]
    else:
        host = "bourd.vkactf.ru"
        
    url = "http://" + host
     
    try:    
        resp = requests.get("http://" + host)
        if resp.status_code != 200:
            print(YELLOW + set_addr.__doc__ + RESET)
            exit(0)
    except requests.RequestException as e:
        print(YELLOW + f"Не удалось подключиться к {url}: {e}" + RESET)
        print(YELLOW + set_addr.__doc__ + RESET)
        exit(0)
        
    return url

def check_admin_page(url: str, session: requests.Session) -> bool:
    try:
        resp = session.get(url, allow_redirects=True)
        if resp.status_code != 200:
            print(RED + f"Не удалось получить страницу: {resp.status_code}" + RESET)
            return False

        # Ищем паттерн на странице
        if '/admin">admino4ka<' in resp.text:
            return True
        return False

    except requests.exceptions.RequestException as e:
        print(RED + f"Ошибка при запросе: {e}" + RESET)
        return False

def get_admin(url):
    global s, Nonce
    print(CYAN +"Вход в админ панель:" + RESET)
    admin_username = input(CYAN + "Enter Admin username: " + RESET)
    admin_pass = input(CYAN + "Enter Admin password: " + RESET)

    if s is None:
        s = requests.Session()

    try:
       
        response = s.get(url + "/login")
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            nonce_input = soup.find("input", {"id": "nonce"})
            nonce = nonce_input["value"] if nonce_input else None
            Nonce = nonce
            if not nonce:
                print(RED + "Ошибка: nonce не найден на странице логина" + RESET)
                exit(1)
        else:
            print(RED + f"Не удалось получить страницу логина: {response.status_code}" + RESET)
            exit(1)

        login_data = {
            "name": admin_username,
            "password": admin_pass,
            "_submit": "ВОЙТИ",
            "nonce": nonce
        }
        
        login_response = s.post(url + "/login", data=login_data)
        if not check_admin_page(url + "/all_rules", s):
            print(RED + "Ошибка: Неверное имя пользователя или пароль админа" + RESET)
            exit(1)
        if login_response.status_code == 200:
            print(GREEN + "Запрос на логин отправлен успешно" + RESET)
        else:
            print(RED + f"Логин не удался, код: {login_response.status_code}, ответ: {login_response.text}" + RESET)
        
    
    except requests.exceptions.RequestException as e:
        print(RED + f"Ошибка при выполнении запроса: {e}" + RESET)

    

def get_name_challenge(writeup_file):
    pattern = r"^\|.*?\n\|.*?\n\|\s*[^|]+\s*\|\s*([^|]+?)\s*\|.*$"
    name = re.search(pattern, writeup_file, re.MULTILINE)
    
    return name

def get_category_challenge(writeup_file):
    pattern = r"^\|.*?\n\|.*?\n\|\s*[^|]+\s*\|\s*[^|]+\s*\|\s*([^|]+?)\s*\|.*$"
    category = re.search(pattern, writeup_file, re.MULTILINE)
    
    return category

def get_description_challenge(writeup_file):
    # Ищем строку с автором, затем ВЕСЬ текст до следующего заголовка или конца файла
    pattern = r"(^> Автор:.*?\n)(.*?)(?=\n\n#|\n\n\||\Z)"
    match = re.search(pattern, writeup_file, re.MULTILINE | re.DOTALL)
    
    if match:
        # Объединяем строку автора и описание, убираем лишние пробелы
        full_text =  match.group(2).strip()[2:]
        return full_text
    return ""

def get_flag():
    text = get_writeup_file()
    pattern = r'vka\{.*?\}' or r'vkakids\{.*?\}' or r'vkactf\{.*?\}' or r'vka*\{.*?\}'
    
    flag =  re.search(pattern, text, re.MULTILINE)
    return flag    

def get_writeup_file():
    folder = Path("../solution")
    target_file = "writeup.md"
    
    matching_file = [f for f in folder.iterdir() if f.is_file() and f.name.lower() == target_file]
    
    if matching_file:
        file_path = matching_file[0]
        writeup_file = file_path.read_text(encoding='utf-8')
        print(GREEN + f"Файл {file_path.name} прочитан!" + RESET)
    else:
        print(RED + f"Файл {target_file} не найден." + RESET)
        
    return writeup_file



def get_task_nonce(url):
    
    resp = s.get(url + "/admin/challenges/new")
    
    match = re.search(r"'csrfNonce':\s*\"([a-f0-9]{64})\"", resp.text)
    if match:
        return match.group(1)
    
    
def add_challenges_first(url):
    
    resp = s.get(url + "/challenges")
    csrf_token = re.search(r"'csrfNonce': \"([a-f0-9]+)\"", resp.text).group(1)
    
    headers = {
        "CSRF-Token" : csrf_token, 
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection" : "keep-alive",
    }
    
    print(CYAN + "Установление параметров для таска" + RESET)
    writeup_file = get_writeup_file()
    
    print(CYAN + "Получение имени таска" + RESET)
    name_challenge = get_name_challenge(writeup_file)
    print(CYAN + "Имя таска: " + RESET, name_challenge.group(1).strip()) 
    
    print(CYAN + "Получение категории таска" + RESET)
    category_challenge = get_category_challenge(writeup_file)  
    print(CYAN + "Категория таска: " + RESET, category_challenge.group(1).strip()) 
       
    print(CYAN + "Получение описания таска" + RESET)
    description_challenge = get_description_challenge(writeup_file) 
    print(CYAN + "Описание таска: " + RESET, description_challenge) 
    
    data = {
            "name" : name_challenge.group(1).strip(),
            "category" : category_challenge.group(1).strip(),
            "challenge_token":"",
            "description" : description_challenge,
            "initial":"1000",
            "decay":"10",
            "minimum":"100",
            "state":"hidden",
            "type":"dynamic"
    }
    
    resp =  s.post(url + '/api/v1/challenges', json=data, headers=headers)
    challenge_id = resp.json()["data"]["id"]
    
    return challenge_id


def add_file(url, task_id):
    
    import shutil
    
    script_dir = Path(__file__).parent   
    project_root = script_dir.parent        
    give_dir = project_root / "give"
    archive_path = project_root / "give.zip"

    print(CYAN + f"Создание архива {archive_path}" + RESET)
    shutil.make_archive(str(archive_path.with_suffix('')), 'zip', str(give_dir))
    
    if not archive_path.exists():
        print(RED + f"Архив не найден: {archive_path}" + RESET)
        return

    task_nonce = get_task_nonce(url)

    with open(archive_path, "rb") as f:
        files = {
            "file": (archive_path.name, f, "application/zip"),
            "nonce": (None, task_nonce),
            "challenge": (None, str(task_id)),
            "type": (None, "challenge")
        }      
    headers = {
        "X-Requested-With": "XMLHttpRequest",
    }    
    
    try:
        response = s.post(url + "/api/v1/files", files=files, headers=headers)
        if response.status_code == 200:
            try:
                print(GREEN + "Файл успешно загружен!" + RESET)
            except ValueError:
                print(RED + f"Ответ не в формате JSON: {response.text}" + RESET)
        else:
            print(RED + f"Ошибка загрузки: {response.status_code}" + RESET)
    except Exception as e:
        print(RED + f"Ошибка при отправке запроса: {e}" + RESET)
    finally:
        if "file" in files and files["file"][1]:
            files["file"][1].close()


def get_mutation_type():
    type_mutation = ""
    data = ""

    print(CYAN + "Если у Вас offline мутация, нажмите Enter, или выберите свой тип" + RESET)
    print(CYAN + "1) offline_mutated (target)" + RESET)
    print(CYAN + "2) online_mutated" + RESET)
    print(CYAN + "3) file_mutated" + RESET)
    print(CYAN + "4) static" + RESET)

    number_mutation = input(CYAN + "Type: " + RESET)

    match number_mutation:
        case '1':
            type_mutation = "offline_mutated"
        case '2':
            type_mutation = "online_mutated"
        case '3':
            type_mutation = "file_mutated"
        case '4':
            type_mutation = "static"
            case_sensitive = input(CYAN + "Sensitive/Insensitive (y/n): " + RESET).lower()
            if case_sensitive == "n":
                data = "case_insensitive"
        case _:
            type_mutation = "offline_mutated"

    return type_mutation, data
    

def add_flags(url, task_id):
    
    print(CYAN + "Добавление флага" + RESET)
    flag_challenge = get_flag()
    
    print(GREEN + "Флаг получен: " + RESET, flag_challenge.group(0).strip())
    type_mutation, data_as_param = get_mutation_type()
    
    if type_mutation == "static":
        data={
            "content" : flag_challenge.group(0).strip(),
            "type" : type_mutation,
            "data": data_as_param,
            "challenge" : task_id
        }
    else:
        data={
            "content" : flag_challenge.group(0).strip(),
            "type" : type_mutation,
            "challenge" : task_id
        }    

    json_body = json.dumps(data)
    extra = ' ' * 8
    final_body = json_body + extra
    
    resp = s.get(url + "/challenges")
    csrf_token = re.search(r"'csrfNonce': \"([a-f0-9]+)\"", resp.text).group(1)
    
    headers = {
        "CSRF-Token" : csrf_token, 
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    try:
        response = s.post(url + '/api/v1/flags', data=final_body, headers=headers)
        if response.status_code == 200:
            try:
                print(GREEN + "Файл успешно загружен!" + RESET)
            except ValueError:
                print(RED + f"Ответ не в формате JSON: {response.text}" + RESET)
        else:
            print(RED + f"Ошибка загрузки: {response.status_code}" + RESET)
    except Exception as e:
        print(RED + f"Ошибка при отправке запроса: {e}" + RESET)



def get_level_tag():
    writeup_file = get_writeup_file()
    pattern = r"^\|.*?\n\|.*?\n\|\s*[^|]+\s*\|\s*[^|]+\s*\|\s*[^|]+\s*\|\s*([^|]+?)\s*\|.*$"
    match = re.search(pattern, writeup_file, re.MULTILINE)
    return match.group(1).strip() if match else None

def get_tags():
    tags = []
    tags.append(get_level_tag())
    print(GREEN + "Сложность таска: " + RESET + tags[0])
    
    print(YELLOW + "Введите дополнительные теги (по одному на строку)." + RESET)
    print(YELLOW + "Чтобы завершить ввод, оставьте строку пустой и нажмите Enter." + RESET)

    while True:
        tag = input(YELLOW + "Тег: " + RESET).strip()
        if not tag:  # пустая строка - конец ввода
            break
        tags.append(tag)
    
    return tags

def add_tags(url, task_id):

    print(CYAN + "Добавление тегов" + RESET)
    tags = get_tags()  
    print(GREEN + "Теги получены: " + RESET, tags)
    
    csrf_token = get_task_nonce(url)
    
    for tag in tags:  
        data = {
                "value" : tag,
                "challenge" : task_id
        }
        
        headers = {
            "CSRF-Token": csrf_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": url,
            "Referer": f"{url}/admin/challenges/{task_id}"
        }   
        
        resp = s.post(url + '/api/v1/tags', json=data, headers=headers) 
        if resp.status_code != 200:
            print(RED + f"Ошибка при добавлении тега {tag}: {resp.status_code}, {resp.text}" + RESET)
        else:
            print(GREEN + f"Тег '{tag}' успешно добавлен" + RESET)
        
    s.get(f"{url}/api/v1/challenges/{task_id}/tags")



def get_conn_info():
    conn_string = ""
    
    print(YELLOW + "Введите строку подключения." + RESET)
    print(YELLOW + "Чтобы завершить ввод, оставьте строку пустой и нажмите Enter." + RESET)
    
    conn_string = input(YELLOW + "Connection info: " + RESET).strip()
    
    return conn_string

def add_conn_info(url, task_id):
    
    print(CYAN + "Добавление conn_info" + RESET)
    conn_info = get_conn_info()
    
    print(CYAN + "conn_info: " + RESET, conn_info)
    
    csrf_token = get_task_nonce(url)
    headers = {
            "CSRF-Token": csrf_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
    }
    
    data= {
        "connection_info" : conn_info,
    }
    
    endpoint = f"/api/v1/challenges/{task_id}"
    resp = s.patch(url + endpoint, json=data, headers=headers)
    
    if resp.status_code != 200:
        print(RED + f"Ошибка при добавлении conn_string {conn_info}: {resp.status_code}, {resp.text}" + RESET)
    else:
        print(GREEN + f"Connection info:'{conn_info}' успешно добавлен" + RESET)


def add_challenge(url):
    task_id = add_challenges_first(url)
    add_file(url, task_id)
    add_flags(url, task_id)
    add_tags(url, task_id)
    add_conn_info(url, task_id)
    print(GREEN + "Таск успешно добавлен!" + RESET)

    
def main():
    url = set_addr()
    get_admin(url)
    add_challenge(url)
    
    
if __name__ == '__main__':
    main()