# Detección de columnas para ataques UNION

Cuando se realiza un ataque `UNION`, existen dos métodos para determinar cuántas columnas devuelve la consulta original:

1. **Usar `ORDER BY` incrementando el índice de columna**

   * Inyectar una serie de `ORDER BY` incrementando el índice hasta que se produzca un error. Ejemplos (cuando el punto de inyección es una cadena entre comillas en la cláusula `WHERE`):

     ```text
     ' ORDER BY 1--
     ' ORDER BY 2--
     ' ORDER BY 3--
     ```
   * Esto modifica la consulta original para ordenar los resultados por diferentes columnas del conjunto de resultados. La columna en `ORDER BY` puede especificarse por índice; cuando el índice excede el número de columnas, se produce un error.

2. **Enviar `UNION SELECT` con distintos números de valores `NULL`**

   * Enviar payloads `UNION SELECT` con un número creciente de `NULL`:

     ```text
     ' UNION SELECT NULL--
     ' UNION SELECT NULL,NULL--
     ' UNION SELECT NULL,NULL,NULL--
     ```
   * Si el número de valores `NULL` no coincide con el número de columnas de la consulta original, se producirá un error.
   * Se usa `NULL` ya que es convertible a la mayoría de tipos de datos comunes, aumentando la probabilidad de éxito cuando el recuento de columnas es correcto.

---

# Solución (lab)

1. Utilice Burp Suite para interceptar y modificar la solicitud que establece el filtro de `category`.
2. Modificar el parámetro `category` asignándole el valor `'+UNION+SELECT+NULL--` y observar que ocurre un error.
3. Modificar `category` para agregar una columna adicional que contenga un valor `NULL`:

   ```text
   '+UNION+SELECT+NULL,NULL--
   ```
4. Continuar agregando valores `NULL` hasta que el error desaparezca y la respuesta incluya contenido adicional con los valores `NULL`.

---

# Sintaxis específica de la base de datos

* **Oracle:** cada `SELECT` debe utilizar `FROM` y especificar una tabla válida. Oracle dispone de la tabla `DUAL` para este fin. Las consultas inyectadas en Oracle pueden verse así:

  ```text
  ' UNION SELECT NULL FROM DUAL--
  ```

* **MySQL:** la secuencia de doble guión (`--`) debe ir seguida de un espacio para indicar un comentario. Alternativamente, se puede usar el carácter `#` para iniciar un comentario.

---

