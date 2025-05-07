// package com.example.gateway_service.controller;

// import org.springframework.boot.autoconfigure.web.WebProperties;
// import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
// import org.springframework.boot.web.error.ErrorAttributeOptions;
// import org.springframework.boot.web.reactive.error.ErrorAttributes;
// import org.springframework.context.ApplicationContext;
// import org.springframework.core.annotation.Order;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.MediaType;
// import org.springframework.http.codec.ServerCodecConfigurer;
// import org.springframework.stereotype.Component;
// import org.springframework.web.reactive.function.BodyInserters;
// import org.springframework.web.reactive.function.server.*;
// import reactor.core.publisher.Mono;

// import java.util.Map;

// @Component
// @Order(-2)
// public class ErrorController extends AbstractErrorWebExceptionHandler {

//     public ErrorController(ErrorAttributes errorAttributes, 
//                            WebProperties.Resources resources, 
//                            ApplicationContext applicationContext,
//                            ServerCodecConfigurer configurer) {
//         super(errorAttributes, resources, applicationContext);
//         this.setMessageWriters(configurer.getWriters());
//     }

//     @Override
//     protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
//         return RouterFunctions.route(RequestPredicates.all(), this::renderErrorResponse);
//     }

//     private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {
//         Map<String, Object> errorPropertiesMap = getErrorAttributes(request, ErrorAttributeOptions.defaults());

//         return ServerResponse.status(HttpStatus.valueOf((Integer) errorPropertiesMap.get("status")))
//                 .contentType(MediaType.APPLICATION_JSON)
//                 .body(BodyInserters.fromValue(errorPropertiesMap));
//     }
// }