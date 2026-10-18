package service.gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import service.gateway.dto.ContextoUsuario;
import service.gateway.dto.RolUsuario;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    private static final String TOKEN = "header.payload.firma";
    private static final UUID USER_ID = UUID.fromString("3f2b8c1e-9a4d-4e2f-8b7a-1c2d3e4f5a6b");
    private static final String ID_FALSO = "00000000-0000-0000-0000-000000000000";

    @Mock
    private JwtValidator jwtValidator;

    @Mock
    private GatewayFilterChain chain;

    private JwtAuthFilter filtro;

    @BeforeEach
    void setUp() {
        filtro = new JwtAuthFilter(new RutasPublicasMatcher(), jwtValidator);
    }

    private ServerWebExchange ejecutarYCapturarExchangeDeLaCadena(MockServerWebExchange exchange) {
        when(chain.filter(any())).thenReturn(Mono.empty());
        filtro.filter(exchange, chain).block();
        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        return captor.getValue();
    }

    @Test
    void filter_rutaPublicaSinTokenConHeadersFalsos_eliminaHeadersYContinua() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/propiedades/1")
                        .header("X-User-Id", ID_FALSO)
                        .header("X-User-Role", "ADMINISTRADOR_CENTRAL"));

        HttpHeaders headers = ejecutarYCapturarExchangeDeLaCadena(exchange).getRequest().getHeaders();

        assertThat(headers.containsHeader("X-User-Id")).isFalse();
        assertThat(headers.containsHeader("X-User-Role")).isFalse();
        verifyNoInteractions(jwtValidator);
    }

    @Test
    void filter_rutaPrivadaSinToken_devuelve401YNoLlamaCadena() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/users/me"));

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain, jwtValidator);
    }

    @Test
    void filter_rutaPrivadaSinTokenConHeadersFalsos_devuelve401() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.delete("/propiedades/1")
                        .header("X-User-Id", ID_FALSO)
                        .header("X-User-Role", "ADMINISTRADOR_CENTRAL"));

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain, jwtValidator);
    }

    @Test
    void filter_tokenValidoEnRutaPrivada_continuaConHeadersDelUsuario() {
        when(jwtValidator.validar(TOKEN)).thenReturn(Mono.just(new ContextoUsuario(USER_ID, RolUsuario.AGENTE)));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN));

        ServerWebExchange enviado = ejecutarYCapturarExchangeDeLaCadena(exchange);

        HttpHeaders headers = enviado.getRequest().getHeaders();
        assertThat(headers.get("X-User-Id")).containsExactly(USER_ID.toString());
        assertThat(headers.get("X-User-Role")).containsExactly("AGENTE");
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void filter_tokenValidoConHeadersFalsos_reemplazaPorLosDelToken() {
        when(jwtValidator.validar(TOKEN)).thenReturn(Mono.just(new ContextoUsuario(USER_ID, RolUsuario.CLIENTE)));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/leads")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN)
                        .header("X-User-Id", ID_FALSO)
                        .header("X-User-Role", "ADMINISTRADOR_CENTRAL"));

        HttpHeaders headers = ejecutarYCapturarExchangeDeLaCadena(exchange).getRequest().getHeaders();

        assertThat(headers.get("X-User-Id")).containsExactly(USER_ID.toString());
        assertThat(headers.get("X-User-Role")).containsExactly("CLIENTE");
        verify(jwtValidator).validar(TOKEN);
    }

    @Test
    void filter_tokenInvalidoEnRutaPrivada_devuelve401YNoLlamaCadena() {
        when(jwtValidator.validar(TOKEN)).thenReturn(Mono.error(new IllegalStateException("firma inválida")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN));

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain);
    }

    @Test
    void filter_tokenInvalidoEnRutaPublica_continuaComoAnonimoSinHeaders() {
        when(jwtValidator.validar(TOKEN)).thenReturn(Mono.error(new IllegalStateException("token expirado")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oficinas/1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN)
                        .header("X-User-Id", ID_FALSO)
                        .header("X-User-Role", "ADMINISTRADOR_CENTRAL"));

        HttpHeaders headers = ejecutarYCapturarExchangeDeLaCadena(exchange).getRequest().getHeaders();

        assertThat(headers.containsHeader("X-User-Id")).isFalse();
        assertThat(headers.containsHeader("X-User-Role")).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @ParameterizedTest(name = "Authorization=\"{0}\" -> 401")
    @ValueSource(strings = {TOKEN, "Basic dXNlcjpwYXNz", "bearer " + TOKEN, "Bearer", "Token " + TOKEN})
    void filter_authorizationSinPrefijoBearerEnRutaPrivada_devuelve401(String authorization) {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/users/me").header(HttpHeaders.AUTHORIZATION, authorization));

        filtro.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(chain, jwtValidator);
    }

    @Test
    void getOrder_siempre_devuelveMenosUno() {
        assertThat(filtro.getOrder()).isEqualTo(-1);
    }
}
