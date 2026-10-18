pub mod apipb {
    #![allow(
        clippy::allow_attributes_without_reason,
        reason = "Tonic-generated bindings emit lint attributes without reasons"
    )]
    #![allow(
        clippy::large_enum_variant,
        reason = "Preserve prost-generated oneof value types from the vendored speaker API"
    )]
    // GoBGP v4.x uses "api" package name
    tonic::include_proto!("api");
}
