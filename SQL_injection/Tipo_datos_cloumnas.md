Un ataque UNION de inyecion SQL le permite recuperar los resultados de una consulta inyectada. Los datos unteresantes nomralmente estan en forma de cadena. 
Esto significa que necesita encontrar una o mas columnas en los resultados de la consulta original cuyo tipo de dato sea compatible con datos de cadena.

Despuesd e determinal la cantidad de columnas requeidas, puedes probar cada columna para probar si puede contener datos de cadena. 
Si la consulta devuelve cuatro columnas debe enviar : 
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--

Si el tipo de datos de la columna no es compatible con los datos de cadena, la consulta inyectada provocará un error en la base de datos, como por ejemplo:
Si no se produce un error y la respuesta de la aplicación contiene algún contenido adicional, incluido el valor de cadena inyectado, entonces la columna correspondiente es adecuada para recuperar datos de cadena.

