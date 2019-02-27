package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.trustengine.client.ApiClient;
import com.cloudentity.libs.trustengine.client.api.AuthzApi;
import com.cloudentity.libs.trustengine.client.model.ValidatorsData;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.cloudentity.examples.trustengine.config.Credentials.*;
import static com.cloudentity.examples.trustengine.config.Credentials.userOAuthAccessToken;
import static com.cloudentity.examples.trustengine.helpers.Commons.abacWithUserContextPolicyName;

/**
 * this class shows how to validate ABAC policy with user context
 *
 * Note: user context is taken from additional access token - to get access token for user follow the instruction
 * in creating-client-app-and-getting-user-access-token.adoc file
 *
 * user access token should be set in Credentials class
 *
 * ONLY_JOHN_ALLOWED should be a simple policy that just checks if user firstName is John - to make below
 * policy verification pass just change user name in self service UI panel to John
 */
public class ABACApplicationPolicyValidationWithUserContextFromUserAccessToken {

  private static Logger log = LoggerFactory.getLogger(ABACApplicationPolicyValidationWithUserContextFromUserAccessToken.class);

  private static final ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  private static AuthzApi authorizationServiceClient = client.buildClient(AuthzApi.class);

  public static void main(String[] args) {
    try {
      log.info("Validating if policy {} holds for user identifier by token {}", abacWithUserContextPolicyName, userOAuthAccessToken);
      authorizationServiceClient.postAuthzApplicationPolicyWithPolicyNameValidate(abacWithUserContextPolicyName, userOAuthAccessToken, new ValidatorsData());
      log.info("Policy validated successfully");
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }
}
