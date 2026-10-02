package service.gateway.dto;


import java.util.UUID;

public record ContextoUsuario(UUID userId, RolUsuario rol) {}