package service.gateway.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.Exceptions;
import service.gateway.dto.ContextoUsuario;
import service.gateway.dto.RolUsuario;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class JwtValidatorTest {

    private static final String KID = "llave-prueba";
    private static final UUID USER_ID = UUID.fromString("3f2b8c1e-9a4d-4e2f-8b7a-1c2d3e4f5a6b");

    private static RSAKey llave;
    private static HttpServer servidorJwks;
    private static JwtValidator validator;

    @BeforeAll
    static void iniciarServidorJwks() throws Exception {
        llave = new RSAKeyGenerator(2048).keyID(KID).generate();
        byte[] jwks = new JWKSet(llave.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);

        servidorJwks = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        servidorJwks.createContext("/.well-known/jwks.json", intercambio -> {
            intercambio.getResponseHeaders().add("Content-Type", "application/json");
            intercambio.sendResponseHeaders(200, jwks.length);
            try (OutputStream cuerpo = intercambio.getResponseBody()) {
                cuerpo.write(jwks);
            }
        });
        servidorJwks.start();

        int puerto = servidorJwks.getAddress().getPort();
        validator = new JwtValidator("http://127.0.0.1:" + puerto + "/.well-known/jwks.json");
    }

    @AfterAll
    static void detenerServidorJwks() {
        servidorJwks.stop(0);
    }

    private static JWTClaimsSet.Builder claimsValidos() {
        Date ahora = new Date();
        return new JWTClaimsSet.Builder()
                .subject(USER_ID.toString())
                .claim("rol", "AGENTE")
                .issueTime(ahora)
                .expirationTime(new Date(ahora.getTime() + 5 * 60 * 1000));
    }

    private static String firmar(JWTClaimsSet claims, RSAKey llaveFirma) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(llaveFirma.getKeyID()).type(JOSEObjectType.JWT).build(),
                claims);
        jwt.sign(new RSASSASigner(llaveFirma));
        return jwt.serialize();
    }

    private static Throwable errorAlValidar(String token) {
        RuntimeException e = assertThrows(RuntimeException.class, () -> validator.validar(token).block());
        return Exceptions.unwrap(e);
    }

    @ParameterizedTest(name = "rol {0}")
    @EnumSource(RolUsuario.class)
    void validar_tokenValido_devuelveContextoUsuario(RolUsuario rol) throws Exception {
        String token = firmar(claimsValidos().claim("rol", rol.name()).build(), llave);

        ContextoUsuario contexto = validator.validar(token).block();

        assertThat(contexto).isEqualTo(new ContextoUsuario(USER_ID, rol));
    }

    @Test
    void validar_tokenExpirado_lanzaBadJOSEException() throws Exception {
        long haceDiezMinutos = System.currentTimeMillis() - 10 * 60 * 1000;
        String token = firmar(claimsValidos()
                .issueTime(new Date(haceDiezMinutos))
                .expirationTime(new Date(haceDiezMinutos + 5 * 60 * 1000))
                .build(), llave);

        assertThat(errorAlValidar(token)).isInstanceOf(BadJOSEException.class);
    }

    @Test
    void validar_tokenFirmadoConOtraLlave_lanzaBadJOSEException() throws Exception {
        RSAKey llaveAtacante = new RSAKeyGenerator(2048).keyID(KID).generate();
        String token = firmar(claimsValidos().build(), llaveAtacante);

        assertThat(errorAlValidar(token)).isInstanceOf(BadJOSEException.class);
    }

    @Test
    void validar_tokenFirmadoConHS256_lanzaBadJOSEException() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KID).build(),
                claimsValidos().claim("rol", "ADMINISTRADOR_CENTRAL").build());
        jwt.sign(new MACSigner("secreto-de-al-menos-treinta-y-dos-bytes!!".getBytes(StandardCharsets.UTF_8)));

        assertThat(errorAlValidar(jwt.serialize())).isInstanceOf(BadJOSEException.class);
    }

    @Test
    void validar_tokenSinFirma_lanzaError() throws Exception {
        String firmado = firmar(claimsValidos().claim("rol", "ADMINISTRADOR_CENTRAL").build(), llave);
        String sinFirma = firmado.substring(0, firmado.lastIndexOf('.') + 1);

        assertThat(errorAlValidar(sinFirma)).isInstanceOfAny(BadJOSEException.class, ParseException.class);
    }

    @ParameterizedTest(name = "token \"{0}\"")
    @ValueSource(strings = {"no-es-un-jwt", "", "a.b.c", "Bearer xyz"})
    void validar_tokenMalformado_lanzaParseException(String token) {
        assertThat(errorAlValidar(token)).isInstanceOf(ParseException.class);
    }

    @Test
    void validar_subNoEsUuid_lanzaIllegalArgumentException() throws Exception {
        String token = firmar(claimsValidos().subject("usuario-123").build(), llave);

        assertThat(errorAlValidar(token)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validar_rolInexistente_lanzaIllegalArgumentException() throws Exception {
        String token = firmar(claimsValidos().claim("rol", "SUPERUSUARIO").build(), llave);

        assertThat(errorAlValidar(token)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validar_sinClaimRol_lanzaNullPointerException() throws Exception {
        String token = firmar(claimsValidos().claim("rol", null).build(), llave);

        assertThat(errorAlValidar(token)).isInstanceOf(NullPointerException.class);
    }
}
