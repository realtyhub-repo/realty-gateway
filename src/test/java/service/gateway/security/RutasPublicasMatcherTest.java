package service.gateway.security;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class RutasPublicasMatcherTest {

    private final RutasPublicasMatcher matcher = new RutasPublicasMatcher();

    @ParameterizedTest(name = "{0} {1} es pública")
    @CsvSource({
            "POST, /auth/login",
            "POST, /auth/register",
            "GET,  /auth/verificar",
            "GET,  /oficinas",
            "GET,  /oficinas/1",
            "GET,  /oficinas/1/agentes",
            "GET,  /agentes/3f2b8c1e-9a4d-4e2f-8b7a-1c2d3e4f5a6b",
            "GET,  /propiedades",
            "GET,  /propiedades/1/fotos"
    })
    void esPublica_rutaPublicaConMetodoCorrecto_devuelveTrue(String metodo, String path) {
        assertThat(matcher.esPublica(HttpMethod.valueOf(metodo), path)).isTrue();
    }

    @ParameterizedTest(name = "{0} {1} es privada")
    @CsvSource({
            "GET,    /users/me",
            "PATCH,  /users/1",
            "POST,   /propiedades",
            "PUT,    /propiedades/1",
            "DELETE, /propiedades/1",
            "GET,    /leads",
            "GET,    /visitas/1",
            "GET,    /contratos/1",
            "GET,    /"
    })
    void esPublica_rutaPrivada_devuelveFalse(String metodo, String path) {
        assertThat(matcher.esPublica(HttpMethod.valueOf(metodo), path)).isFalse();
    }

    @ParameterizedTest(name = "{0} {1} no es pública")
    @CsvSource({
            "POST,   /oficinas",
            "POST,   /agentes/1",
            "PUT,    /auth/login",
            "DELETE, /oficinas/1",
            "POST,   /propiedades/1",
            "PATCH,  /agentes/1"
    })
    void esPublica_metodoIncorrectoEnRutaPublica_devuelveFalse(String metodo, String path) {
        assertThat(matcher.esPublica(HttpMethod.valueOf(metodo), path)).isFalse();
    }

    @ParameterizedTest(name = "GET {0} no es pública")
    @ValueSource(strings = {"/agentes/1/algo", "/agentes/1/propiedades/2", "/agentes"})
    void esPublica_agenteConSubrecursoOSinId_devuelveFalse(String path) {
        assertThat(matcher.esPublica(HttpMethod.GET, path)).isFalse();
    }

    @ParameterizedTest(name = "null {0} no es pública")
    @ValueSource(strings = {"/auth/login", "/oficinas", "/agentes/1", "/propiedades/1"})
    void esPublica_metodoNull_devuelveFalse(String path) {
        assertThat(matcher.esPublica(null, path)).isFalse();
    }
}
