package service.gateway.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class CorsConfigTest {

    @Mock
    private WebFilterChain chain;

    private final CorsWebFilter filtro = new CorsConfig().corsWebFilter();

    private MockServerWebExchange preflightDesde(String origen) {
        return MockServerWebExchange.from(
                MockServerHttpRequest.options("http://localhost:8080/propiedades")
                        .header(HttpHeaders.ORIGIN, origen)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.GET.name()));
    }


    @ParameterizedTest(name = "origen {0} permitido")
    @ValueSource(strings = {
            "https://www.realty-hub.site",
            "https://realty-hub.site",
            "https://app.realty-hub.site",
            "http://localhost:5500"
    })
    void corsWebFilter_origenConfigurado_permiteOrigen(String origen) {
        MockServerWebExchange exchange = preflightDesde(origen);

        filtro.filter(exchange, chain).block();

        HttpHeaders respuesta = exchange.getResponse().getHeaders();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
        assertThat(respuesta.getAccessControlAllowOrigin()).isEqualTo(origen);
        assertThat(respuesta.getAccessControlAllowCredentials()).isTrue();
    }

    @ParameterizedTest(name = "origen {0} rechazado")
    @ValueSource(strings = {"https://evil.com", "https://realty-hub.site.evil.com", "http://realty-hub.site", "http://localhost:3000"})
    void corsWebFilter_origenNoConfigurado_rechazaConForbidden(String origen) {
        MockServerWebExchange exchange = preflightDesde(origen);

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getAccessControlAllowOrigin()).isNull();
        verifyNoInteractions(chain);
    }

    @Test
    void corsWebFilter_headerNoPermitidoEnPreflight_rechazaConForbidden() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.options("http://localhost:8080/propiedades")
                        .header(HttpHeaders.ORIGIN, "https://app.realty-hub.site"/)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.GET.name())
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "X-User-Role"));

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
