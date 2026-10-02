package service.gateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final RutasPublicasMatcher rutasPublicasMatcher;
    private final JwtValidator jwtValidator;

    public JwtAuthFilter(RutasPublicasMatcher rutasPublicasMatcher, JwtValidator jwtValidator) {
        this.rutasPublicasMatcher = rutasPublicasMatcher;
        this.jwtValidator = jwtValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest requestLimpio =  exchange.getRequest().mutate()
                .headers(headers->{
                    headers.remove("X-User-Id");
                    headers.remove("X-User-Role");
                })
                .build();

        String path = requestLimpio.getPath().value();
        HttpMethod metodo = requestLimpio.getMethod();
        boolean esPublica = rutasPublicasMatcher.esPublica(metodo,path);

        String authHeader = requestLimpio.getHeaders().getFirst("Authorization");
        boolean traeToken = authHeader!=null && authHeader.startsWith("Bearer ");

        if(!esPublica && !traeToken){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        if(esPublica && !traeToken){
            return chain.filter(exchange.mutate().request(requestLimpio).build());
        }

        String token = authHeader.substring(7);

        return jwtValidator.validar(token)
                .flatMap(contexto ->{
                    ServerHttpRequest requestConHeaders = requestLimpio.mutate()
                            .header("X-User-Id", contexto.userId().toString())
                            .header("X-User-Role", contexto.rol().name())
                            .build();
                    return chain.filter(exchange.mutate().request(requestConHeaders).build());
                })
                .onErrorResume(e->{
                    if(esPublica){
                        return chain.filter(exchange.mutate().request(requestLimpio).build());
                    }

                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();

                });

    }

    @Override
    public int getOrder() {
        return -1;
    }
}
