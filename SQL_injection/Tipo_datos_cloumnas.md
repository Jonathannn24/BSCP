# Detección de columnas compatibles con cadenas para ataques UNION

Un ataque `UNION` de inyección SQL permite recuperar los resultados de una consulta inyectada. Los datos interesantes normalmente están en forma de cadena; por tanto, es necesario identificar una o más columnas en los resultados de la consulta original cuyo tipo de dato sea compatible con cadenas.

## Paso 1 — Obtener el número de columnas

(Según métodos previos: `ORDER BY` incrementando el índice o `UNION SELECT` con `NULL` repetidos hasta que deje de dar error.)

## Paso 2 — Probar qué columnas aceptan cadenas

Si la consulta original devuelve cuatro columnas, probar enviando payloads con una cadena `'a'` en cada posición:

```text
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

* Si el tipo de dato de la columna no es compatible con cadenas, la consulta inyectada provocará un error en la base de datos.
* Si no hay error y la respuesta de la aplicación contiene contenido adicional (incluido el valor de cadena inyectado), entonces la columna correspondiente es adecuada para recuperar datos de cadena.

---

