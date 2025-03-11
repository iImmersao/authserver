package com.iimmersao.authserver.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<SavedUserDetails, String> {

    public SavedUserDetails findByUserName(String firstName);
}
