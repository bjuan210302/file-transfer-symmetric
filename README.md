# Transferencia de archivos con clave simetrica
## ¿Como hicieron el programa?
Primero se implementó la conexión cliente-servidor a través de sockets. Luego revisamos la libreria de java security en busqueda de los metodos que necesitabamos para la encriptación y la desencriptación y el DiffieHelman.
## Dificultades
Las dificultades que encontramos mientras realizabamos el proyecto fue de como conectar un proyecto corriendo en simultaneo ya en una red,
además de que no teniamos una idea clara de como realizar el SHA-256, por lo cual tuvimos que investigar en internet para realizarlo con la libreria propia
de java security.
También tuvimos problemas con el plantamiento del Diffie-Hellman porque no sabiamos bien como empezar la logica desde el cliente, ya que este es el que negocia la clave. Tuvimos que leer sobre como funciona esa implementación en Java.

## Conclusiones
- Gracias a este proyecto tuvimos un mayor acercamiento (y uno más real) al uso de algoritmos para comunicación segura, aplicando lo aprendido sobre AES y Diffie-Hellman en un proyecto cliente-servidor, y también aprendimos que gracias al cifrado, se obtiene una mayor seguridad durante las conversaciones y/o transferencias de archivos.
- Tambien nos dimos cuenta que hacer una aplicación segura puede llegar a ser bastante complejo incluso para aplicaciones mas simples, por lo que una implementación completa en la web o en un celular, podria resultar muy laboriosa.
