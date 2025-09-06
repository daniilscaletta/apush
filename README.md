# 🚀 apush – Тулза для автоматизированной загрузки тасков в CTFd

Скрипт для автоматической загрузки тасков в CTFd.  
Берёт данные из `solution/writeup.md`, упаковывает файлы из `give/` и сам создаёт таск со всеми полями, флагами и тегами.

---

## 📦 Установка

```bash
git clone https://github.com/username/apush.git
cd apush
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt

cd .. && mv apush/ /path/to/project/solution
```

## ⚙️ Структура проекта

```bash
    apush/
    ├── myenv/           # виртуальное окружение
    ├── script.py        # основной скрипт
    ├── start.sh         # запуск с активацией окружения
    ├── requirements.txt # файл с зависимостями
    └── README.md        # описание тулзы
```

## ▶️ Запуск

Через start.sh:

```bash
./start.sh
```
Указать только хост:

```bash
./start.sh example.com
```

Указать хост и порт:

```bash
./start.sh 90.156.225.90 8000
```
Или напрямую:

```bash
python3 script.py <host[:port]>
```



## 📝 Использование

1) Подготовить solution/writeup.md (с описанием таска, категорией, тегами, флагом).
2) Сложить раздаваемые файлы в give/.
3) Сложить папку apush в папку solution/ (вместе с райтапом)
4) Запустить ./start.sh.
5) Ввести логин и пароль админа.
6) Скрипт сам создаст задачу, добавит файлы, описание, флаг и теги.


## 💡 Примеры

```bash
./start.sh                   # подключение к bourd.vkactf.ru
./start.sh example.com
./start.sh 90.156.225.90 8000 
```

