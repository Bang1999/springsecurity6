package com.eazybytes.model;

// record는 setter없고, getter, hashCode(), equals() ,toString() 제공
public record LoginRequestDTO(String username, String password) {
}
