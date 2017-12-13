/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

@RequestMapping("/key-providers")
@RestController
public class KeyProviderEndpoints {

    protected static Log logger = LogFactory.getLog(KeyProviderEndpoints.class);

    private final KeyProviderProvisioning keyProviderProvisioning;
    private final KeyProviderValidator keyProviderValidator;

    public KeyProviderEndpoints(KeyProviderProvisioning keyProviderProvisioning, KeyProviderValidator keyProviderValidator) {
        this.keyProviderProvisioning = keyProviderProvisioning;
        this.keyProviderValidator = keyProviderValidator;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<KeyProvider> createKeyProvider(@RequestBody KeyProvider body) {
        String zoneId = IdentityZoneHolder.get().getId();
        body.setIdentityZoneId(zoneId);
        keyProviderValidator.validate(body);
        KeyProvider created = keyProviderProvisioning.create(body);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<SamlServiceProvider> updateKeyProvider(@PathVariable String id,
                                                                     @RequestBody SamlServiceProvider body) throws MetadataProviderException {
        SamlServiceProvider existing = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        String zoneId = IdentityZoneHolder.get().getId();
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        if (!body.configIsValid()) {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }
        body.setEntityId(existing.getEntityId());

        samlValidator.validateSamlServiceProvider(body);

        SamlServiceProvider updatedSp = serviceProviderProvisioning.update(body, zoneId);
        return new ResponseEntity<>(updatedSp, OK);
    }

    @RequestMapping(method = GET)
    public ResponseEntity<List<SamlServiceProvider>> retrieveServiceProviders(
        @RequestParam(value = "active_only", required = false) String activeOnly) {
        Boolean retrieveActiveOnly = Boolean.valueOf(activeOnly);
        List<SamlServiceProvider> serviceProviderList =
            serviceProviderProvisioning.retrieveAll(retrieveActiveOnly,
                                                    IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProviderList, OK);
    }

    @RequestMapping(value = "{id}", method = GET)
    public ResponseEntity<SamlServiceProvider> retrieveServiceProvider(@PathVariable String id) {
        SamlServiceProvider serviceProvider = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProvider, OK);
    }

    @RequestMapping(value = "{id}", method = DELETE)
    public ResponseEntity<SamlServiceProvider> deleteServiceProvider(@PathVariable String id) {
        SamlServiceProvider serviceProvider = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        serviceProviderProvisioning.delete(id, IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProvider, OK);
    }

    @ExceptionHandler(MetadataProviderException.class)
    public ResponseEntity<String> handleMetadataProviderException(MetadataProviderException e) {
        if (e.getMessage().contains("Duplicate")) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        } else {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @ExceptionHandler(JsonUtils.JsonUtilException.class)
    public ResponseEntity<String> handleMetadataProviderException() {
        return new ResponseEntity<>("Invalid provider configuration.", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EmptyResultDataAccessException.class)
    public ResponseEntity<String> handleProviderNotFoundException() {
        return new ResponseEntity<>("Provider not found.", HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(SamlSpAlreadyExistsException.class)
    public ResponseEntity<String> handleDuplicateServiceProvider(){
        return new ResponseEntity<>("SAML SP with the same entity id already exists.", HttpStatus.CONFLICT);
    }

}
