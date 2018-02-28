/*
 * Copyright (c) 2016-2018 Red Hat, Inc.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
package com.redhat.che.multitenant;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.eclipse.che.api.core.BadRequestException;
import org.eclipse.che.api.core.ConflictException;
import org.eclipse.che.api.core.ForbiddenException;
import org.eclipse.che.api.core.NotFoundException;
import org.eclipse.che.api.core.ServerException;
import org.eclipse.che.api.core.UnauthorizedException;
import org.eclipse.che.api.workspace.server.spi.InfrastructureException;
import org.eclipse.che.commons.annotation.Nullable;
import org.eclipse.che.commons.subject.Subject;
import org.eclipse.che.multiuser.keycloak.token.provider.service.KeycloakTokenProvider;

/**
 * Retrieves Openshift user token by keycloak token from {@link Subject}.
 *
 * @author Oleksandr Garagatyi
 */
@Singleton
public class OpenshiftUserTokenProvider {

  private static final int CACHE_TIMEOUT_MINUTES = 10;
  private static final int CONCURRENT_USERS = 500;

  private KeycloakTokenProvider keycloakTokenProvider;
  private LoadingCache<String, String> tokenCache;

  @Inject
  public OpenshiftUserTokenProvider(KeycloakTokenProvider keycloakTokenProvider) {
    this.keycloakTokenProvider = keycloakTokenProvider;
    this.tokenCache =
        CacheBuilder.newBuilder()
            .maximumSize(CONCURRENT_USERS)
            .expireAfterWrite(CACHE_TIMEOUT_MINUTES, TimeUnit.MINUTES)
            .build(CacheLoader.from(this::loadOpenShiftTokenForUser));
  }

  /**
   * Returns Openshift token corresponding to a keycloak token retrieved from provided {@link
   * Subject}
   *
   * @param subject subject with user's keycloak token
   * @return Openshift user token
   * @throws InfrastructureException when there is no keycloak token in subject or OSO token
   *     retrieval failed
   */
  public String getToken(Subject subject) throws InfrastructureException {
    checkSubject(subject);

    String keycloakToken = subject.getToken();
    if (keycloakToken == null) {
      throw new InfrastructureException(
          "User Openshift token is needed but cannot be retrieved since there is no Keycloak token for user: "
              + getUserDescription(subject));
    }
    try {
      return tokenCache.get(keycloakToken);
    } catch (ExecutionException e) {
      throw new InfrastructureException(
          "Could not retrieve OSO token from Keycloak token for user: "
              + getUserDescription(subject),
          e.getCause());
    }
  }

  private void checkSubject(Subject subject) throws InfrastructureException {
    if (subject == null) {
      throw new InfrastructureException("No Subject is found to perform this action");
    }
    if (subject == Subject.ANONYMOUS) {
      throw new InfrastructureException(
          "The anonymous subject is used, and won't be able to perform this action");
    }
  }

  private String getUserDescription(Subject subject) {
    return subject.getUserName() + "(" + subject.getUserId() + ")";
  }

  @Nullable
  private String loadOpenShiftTokenForUser(String keycloakToken) {
    try {
      return keycloakTokenProvider.obtainOsoToken("Bearer " + keycloakToken);
    } catch (ServerException
        | UnauthorizedException
        | ForbiddenException
        | NotFoundException
        | ConflictException
        | BadRequestException
        | IOException e) {
      throw new RuntimeException("Could not retrieve OSO token from Keycloak token", e);
    }
  }
}
