## RESTful сервис, который работает с шифром Цезаря

Логика работы шифра **[здесь](https://github.com/rtemka/caesarcypher)**

### **Использование**

#### Запуск сервера

##### **Docker**

```bash
docker build -t cypherservice .
docker run -it --rm -p 8080:8080 --name cypherservice cypherservice
```

##### **Или из исходника**

```bash
go install ./cmd/service/service.go
service
# start listening on localhost:8080
```

#### **Шифрование**

```bash
curl -d @data-to-encrypt.txt "http://localhost:8080/cyphers/caesar?mode=encode&key=23" > response.txt
```

#### **Дешифровка**

```bash
#  by key
curl -d @data-to-decrypt.txt "http://localhost:8080/cyphers/caesar?mode=decode&key=23" > response.txt

#  brute-force
curl -d @data-to-decrypt.txt "http://localhost:8080/cyphers/caesar?mode=decode&method=brute-force" > response.txt

# frequency analysis
curl -d @data-to-decrypt.txt "http://localhost:8080/cyphers/caesar?mode=encode&method=freq" > response.txt
```