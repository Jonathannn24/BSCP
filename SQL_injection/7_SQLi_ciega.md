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

