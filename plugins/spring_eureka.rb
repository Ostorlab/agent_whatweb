Plugin.define do
  name "Spring Eureka"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Eureka refers to Spring Cloud Netflix Eureka, a service discovery tool. It is part of the Spring Cloud Netflix stack, designed to facilitate the management of microservices in a distributed system.
"
  website "https://cloud.spring.io/spring-cloud-netflix/reference/html/"

  matches [
    {
      :search => "title",
      :regexp => /<title>Eureka<\/title>/,
      :name => "Eureka Title Tag"
    },
  ]
end