# Uso de un ataque UNION de inyección SQL para recuperar datos interesantes

Cuando se hays visto el numero de columnas devueltas por la consulta original y y hayado columnas que puedan tener datos de cadenas.Se pueden recuperar datos
La consulta original devuelve dos columnas, ambas pueden contener datos de cadena.
El punto de inyección es una cadena entre comillas dentro del WHERE cláusula.
La base de datos contiene una tabla llamada users con las columnas username y password.
En este ejemplo, puede recuperar el contenido del users tabla enviando la entrada:
' UNION SELECT usernae, password FROM users--
Para realizar este ataque es necesario saber que existe una tabla llamada users con dos columnas llamadas username y password. Sin esta información, tendrías que adivinar los nombres de las tablas y columnas.

