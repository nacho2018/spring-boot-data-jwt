# spring-boot-data-jwt
proyecto de pruebas curso spring5 con JWT
El proyecto se basa en spring-boot-datta-jpa pero está modificado para permitir transacciones bajo seguridad de envío de un token.

Pruebas con postman
---------------------

POST : https://localhost:8080/api/login
Si recibimos un 200 ok, veremos un json en la respuesta con el token de seguridad.
Probar con un body JSON tal éste:
{"username" : "admin" , "password" : "12345"}, tiene ROLE_ADMIN y ROLE_USER
o
{"username" : "andres" , "password" : "12345"} tiene ROLE_USER
Copiarlo y verificarlo en https://jwt.io para ver el payload.

Abrir otra request de postman y solicitar: https://localhost:8080/api/clientes/listar y en Authorization > Type, Bearer token y pegarlo antes de la llamada.
