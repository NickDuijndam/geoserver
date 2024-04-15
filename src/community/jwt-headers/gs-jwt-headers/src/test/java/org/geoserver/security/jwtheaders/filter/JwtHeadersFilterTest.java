/* (c) 2024 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.jwtheaders.filter;

import java.io.IOException;
import org.geoserver.security.jwtheaders.JwtConfiguration;
import org.geoserver.security.jwtheaders.filter.details.JwtHeadersWebAuthenticationDetails;
import org.geoserver.test.GeoServerAbstractTestSupport;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;

public class JwtHeadersFilterTest {

    @Test
    public void testExistingAuthIsFromThisConfig() throws IOException {
        GeoServerJwtHeadersFilterConfig config1 = new GeoServerJwtHeadersFilterConfig();
        config1.setId("abc123");
        GeoServerJwtHeadersFilter filter1 = new GeoServerJwtHeadersFilter();
        filter1.initializeFromConfig(config1);

        GeoServerJwtHeadersFilterConfig config2 = new GeoServerJwtHeadersFilterConfig();
        config2.setId("aaaaaaaaaaa111111111111111");
        GeoServerJwtHeadersFilter filter2 = new GeoServerJwtHeadersFilter();
        filter2.initializeFromConfig(config1);

        // trivial cases

        // no existing auth
        Assert.isTrue(!filter1.existingAuthIsFromThisConfig(null));
        // not from us
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(null, null, null);
        Assert.isTrue(!filter1.existingAuthIsFromThisConfig(auth));

        // details, but wrong type
        auth.setDetails(new WebAuthenticationDetails(null, null));
        Assert.isTrue(!filter1.existingAuthIsFromThisConfig(auth));

        // more complex cases
        // details is JwtHeaders, but wrong id
        auth.setDetails(
                new JwtHeadersWebAuthenticationDetails(
                        config2.getId(),
                        new GeoServerAbstractTestSupport.GeoServerMockHttpServletRequest("", "")));
        Assert.isTrue(!filter1.existingAuthIsFromThisConfig(auth));

        // details is JwtHeaders,right id
        auth.setDetails(
                new JwtHeadersWebAuthenticationDetails(
                        config1.getId(),
                        new GeoServerAbstractTestSupport.GeoServerMockHttpServletRequest("", "")));
        Assert.isTrue(filter1.existingAuthIsFromThisConfig(auth));
    }

    @Test
    public void testPrincipleHasChanged() throws IOException {
        GeoServerJwtHeadersFilterConfig config1 = new GeoServerJwtHeadersFilterConfig();
        config1.setId("abc123");
        GeoServerJwtHeadersFilter filter1 = new GeoServerJwtHeadersFilter();
        filter1.initializeFromConfig(config1);

        // trivial cases
        Assert.isTrue(!filter1.principleHasChanged(null, null));
        Assert.isTrue(!filter1.principleHasChanged(null, "aaa"));

        UsernamePasswordAuthenticationToken auth_aaa =
                new UsernamePasswordAuthenticationToken("aaa", null, null);
        UsernamePasswordAuthenticationToken auth_bbb =
                new UsernamePasswordAuthenticationToken("bbb", null, null);

        // aaa->aaa
        Assert.isTrue(!filter1.principleHasChanged(auth_aaa, "aaa"));

        /// bbb->aaa
        Assert.isTrue(filter1.principleHasChanged(auth_bbb, "aaa"));
    }

    @Test
    public void testHeaderWithBearerPrefix() throws IOException {
        String header =
                "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItWEdld190TnFwaWRrYTl2QXNJel82WEQtdnJmZDVyMlNWTWkwcWMyR1lNIn0.eyJleHAiOjE3MDcxNTMxNDYsImlhdCI6MTcwNzE1Mjg0NiwiYXV0aF90aW1lIjoxNzA3MTUyNjQ1LCJqdGkiOiJlMzhjY2ZmYy0zMWNjLTQ0NmEtYmU1Yy04MjliNDE0NTkyZmQiLCJpc3MiOiJodHRwczovL2xvZ2luLWxpdmUtZGV2Lmdlb2NhdC5saXZlL3JlYWxtcy9kYXZlLXRlc3QyIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImVhMzNlM2NjLWYwZTEtNDIxOC04OWNiLThkNDhjMjdlZWUzZCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImxpdmUta2V5MiIsIm5vbmNlIjoiQldzc2M3cTBKZ0tHZC1OdFc1QlFhVlROMkhSa25LQmVIY0ZMTHZ5OXpYSSIsInNlc3Npb25fc3RhdGUiOiIxY2FiZmU1NC1lOWU0LTRjMmMtODQwNy03NTZiMjczZmFmZmIiLCJhY3IiOiIwIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtZGF2ZS10ZXN0MiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJsaXZlLWtleTIiOnsicm9sZXMiOlsiR2Vvc2VydmVyQWRtaW5pc3RyYXRvciJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcGhvbmUgb2ZmbGluZV9hY2Nlc3MgbWljcm9wcm9maWxlLWp3dCBwcm9maWxlIGFkZHJlc3MgZW1haWwiLCJzaWQiOiIxY2FiZmU1NC1lOWU0LTRjMmMtODQwNy03NTZiMjczZmFmZmIiLCJ1cG4iOiJkYXZpZC5ibGFzYnlAZ2VvY2F0Lm5ldCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiYWRkcmVzcyI6e30sIm5hbWUiOiJkYXZpZCBibGFzYnkiLCJncm91cHMiOlsiZGVmYXVsdC1yb2xlcy1kYXZlLXRlc3QyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJkYXZpZC5ibGFzYnlAZ2VvY2F0Lm5ldCIsImdpdmVuX25hbWUiOiJkYXZpZCIsImZhbWlseV9uYW1lIjoiYmxhc2J5IiwiZW1haWwiOiJkYXZpZC5ibGFzYnlAZ2VvY2F0Lm5ldCJ9.fHzXd7oISnqWb09ah9wikfP2UOBeiOA3vd_aDg3Bw-xcfv9aD3CWhAK5FUDPYSPyj4whAcknZbUgUzcm0qkaI8V_aS65F3Fug4jt4nC9YPL4zMSJ5an4Dp6jlQ3OQhrKFn4FwaoW61ndMmScsZZWEQyj6gzHnn5cknqySB26tVydT6q57iTO7KQFcXRdbXd6GWIoFGS-ud9XzxQMUdNfYmsDD7e6hoWhe9PJD9Zq4KT6JN13hUU4Dos-Z5SBHjRa6ieHoOe9gqkjKyA1jT1NU42Nqr-mTV-ql22nAoXuplpvOYc5-09-KDDzSDuVKFwLCNMN3ZyRF1wWuydJeU-gOQ";

        GeoServerJwtHeadersFilterConfig config1 = new GeoServerJwtHeadersFilterConfig();
        config1.setId("abc123");
        config1.setUserNameHeaderAttributeName(HttpHeaders.AUTHORIZATION);
        config1.setUserNameJsonPath("name");
        config1.setValidateToken(true);
        config1.setUserNameFormatChoice(JwtConfiguration.UserNameHeaderFormat.JWT);

        GeoServerJwtHeadersFilter filter1 = new GeoServerJwtHeadersFilter();
        filter1.initializeFromConfig(config1);

        MockHttpServletRequest request =
                new GeoServerAbstractTestSupport.GeoServerMockHttpServletRequest("", "");
        request.addHeader(HttpHeaders.AUTHORIZATION, header);

        String userName = filter1.getPreAuthenticatedPrincipalName(request);
        Assert.notNull(userName);
    }
}
