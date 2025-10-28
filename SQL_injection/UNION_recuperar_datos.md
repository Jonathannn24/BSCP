# Uso de un ataque UNION de inyección SQL para recuperar datos interesantes

Cuando ya se ha determinado el número de columnas devueltas por la consulta original y se han identificado columnas que aceptan datos de tipo cadena, es posible recuperar datos.

## Escenario de ejemplo

* La consulta original devuelve **dos columnas**, y **ambas** aceptan datos de cadena.
* El punto de inyección es una cadena entre comillas dentro de la cláusula `WHERE`.
* Existe una tabla `users` con las columnas `username` y `password`.

## Payload para recuperar datos

Enviar la siguiente entrada para recuperar `username` y `password` de la tabla `users`:

```text
' UNION SELECT username, password FROM users--
```

## Nota importante

Para que este ataque funcione es necesario conocer la existencia de la tabla `users` y los nombres de sus columnas (`username`, `password`). Sin esa información, sería necesario adivinar o enumerar los nombres de tablas y columnas.

---


