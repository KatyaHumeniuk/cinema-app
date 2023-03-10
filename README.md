# cinema-app
## Project description
`A stateless web-app that represents a cinema's ticket booking system with registration or authentication process for access and based on Hibernate and Spring frameworks.`
## Features
- register (all new users will be assigned the USER role)
- login as a USER (you can use an existing account or create a new one)
- login as an ADMIN (you can use an existing account)
  ##### The following functions are available for the USER role:
- get all cinema halls;
- get all movies;
- get all available movie sessions;
- get a shopping cart of the user;
- add tickets by movie session into the shopping cart;
- complete an order;
- find all orders of the user.  
  ##### The following functions are available for the ADMIN role:
- get all cinema halls;
- add new cinema hall;
- get all movies;
- add new movie;
- get all available movie sessions;
- add new movie session;
- delete a movie session;
- get user by email.
## Implementation details
- The `config package` is responsible for configuring Spring
- The `dao package` is responsible for communication with the database.
- The `controller package` is responsible for client-server interaction.
- The `model package` represents the application objects, which are also Entities - tables in the database.
- The `DTO package` represents objects for communication with users and the application.
- The `service package` contains all classes with business logic.
- The `service package` also includes `DTO mappers` - classes for converting DTOs into entities and vice versa;
- The `jwt package` provides a JWT token implementation for creating a stateless application.
- The `lib package` contains some custom validation of DTO fields (email and password validation). For other fields in DTO classes, Hibernate Validate annotations are used.
- `CustomGlobalExceptionHandler` – A class that handles exceptions (when the method argument is invalid) and returns a JSON ResponseEntity based on the result.
- The `exception package` contains three custom exceptions - AuthenticationException, DataProcessingException, InvalidJwtAuthenticationException)
## Structure
Project based on Three-Tier architecture:  
- **Controllers (The application logic tier)** - is where users interact with the application. It processes users' requests and responds to them
- **Services (The application logic tier)** - represents all business logic of the application.
- **DAO (The data tier)** - is where all the data used in your application are stored, represents interaction with the database.
## Application technologies:
- JDK 11
- Apache Maven 3.3.2
- Apache Tomcat 9.0.50
- MySQL 8.0.31
- Hibernate 5.6.14.Final
- Hibernate Validator 6.1.6.Final
- Spring Framework 5.3.20
- Spring MVC 5.3.20
- Spring Security 5.6.10
## Installation
1. Download and install the [JDK](https://www.oracle.com/cis/java/technologies/downloads/#java11) (it uses Java 11).
2. Download and install servlet container ([Apache Tomcat](https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.50/bin/)) (it uses Tomcat 9.0.50).
3. Download and install [MySQL Server](https://dev.mysql.com/downloads/).
4. Download and install [MySQL Workbench](https://www.mysql.com/products/workbench/).
5. Create the schema in MySql Workbench.
6. Fork this repository.
7. Clone the project to your computer.
8. Add your `database URL`, `login`, `password` and `DB driver` in `src/main/resources/db.properties`. Example:
```bash
db.driver=com.mysql.cj.jdbc.Driver
db.url=jdbc:mysql://localhost:3306/cinema?serverTimezone=UTC
db.user=root
db.password=1234
```
9. Configure Apache Tomcat. Artifact: war-exploded artifact, Application context: "/".
10. Run the project. 
11. You can use Postman (or another utility) for testing the application.


