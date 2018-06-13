//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Tests;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Jwt.Tests
{
    public class JsonWebTokenTests
    {

        // Test checks to make sure that the JsonWebToken payload is correctly converted to IEnumerable<Claim>.
        [Fact]
        public void GetClaimsFromJObject()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.Payload, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;
            IdentityComparer.AreEqual(Default.PayloadClaims, claims, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the 'Audiences' claim can be successfully retrieved when multiple audiences are present.
        // It also checks that the rest of the claims match up as well
        [Fact]
        public void GetMultipleAudiences()
        {
            var context = new CompareContext();
            var tokenString = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UxLmNvbSIsImh0dHA6Ly9EZWZhdWx0LkF1ZGllbmNlMi5jb20iLCJodHRwOi8vRGVmYXVsdC5BdWRpZW5jZTMuY29tIiwiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2U0LmNvbSJdLCJleHAiOjE1Mjg4NTAyNzgsImlhdCI6MTUyODg1MDI3OCwiaXNzIjoiaHR0cDovL0RlZmF1bHQuSXNzdWVyLmNvbSIsIm5vbmNlIjoiRGVmYXVsdC5Ob25jZSIsInN1YiI6InVybjpvYXNpczpuYW1zOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6WDUwOVN1YmplY3ROYW1lIn0.";
            var jsonWebToken = new JsonWebToken(tokenString);
            var jwtSecurityToken = new JwtSecurityToken(tokenString);
            IdentityComparer.AreEqual(jsonWebToken.Claims, jwtSecurityToken.Claims);
            IdentityComparer.AreEqual(jsonWebToken.Audiences, jwtSecurityToken.Audiences, context);
            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
