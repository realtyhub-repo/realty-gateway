package service.gateway.security;


import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class RutasPublicasMatcher {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final List<RutaPublica> RUTAS_PUBLICAS = List.of(
            new RutaPublica(HttpMethod.POST, "/auth/**"),
            new RutaPublica(HttpMethod.GET, "/auth/**"),
            new RutaPublica(HttpMethod.GET, "/oficinas/**"),
            new RutaPublica(HttpMethod.GET, "/agentes/*"),
            new RutaPublica(HttpMethod.GET, "/propiedades/**")
    );

    public boolean esPublica(HttpMethod metodo, String path) {
        return RUTAS_PUBLICAS.stream()
                .anyMatch(ruta -> ruta.metodo() == metodo && pathMatcher.match(ruta.patron(), path));
    }

    private record RutaPublica(HttpMethod metodo, String patron) {}
}