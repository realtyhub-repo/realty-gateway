# Realty Gateway

Realty Gateway es el componente que funciona como punto de entrada para las solicitudes dirigidas a RealtyHub. Se encarga de enrutar las peticiones hacia los microservicios correspondientes y facilitar la comunicación entre los clientes y los diferentes componentes de la plataforma.

## Funcionalidades

- Enrutamiento de las peticiones hacia cada microservicio.
- Validación del token JWT de los usuarios autenticados.
- Envío del identificador y el rol del usuario a los servicios internos.

## Tecnologías

Java 21, Spring Boot y Spring Cloud Gateway.

## Puerto

El servicio se ejecuta en el puerto `8080` y es el único punto de entrada público de la plataforma.
