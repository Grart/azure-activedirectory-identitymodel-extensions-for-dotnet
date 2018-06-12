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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tests;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Jwt.Tests
{
    public class JsonWebTokenHandlerTests
    {
        // Tests checks to make sure that the token string created by the JsonWebTokenHandler is consistent with the 
        // token string created by the JwtSecurityTokenHandler.
        [Theory, MemberData(nameof(CreateTokenTheoryData))]
        public void CreateToken(CreateTokenTheoryData theoryData)
        {
            IdentityModelEventSource.ShowPII = true;
            var context = TestUtilities.WriteHeader($"{this}.CreateToken", theoryData);
            try
            {
                string jwtFromJwtHandler = theoryData.TokenHandler.CreateEncodedJwt(theoryData.TokenDescriptor);
                string jwtFromJsonHandler = new JsonWebTokenHandler().CreateToken(theoryData.Payload, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);

                theoryData.TokenHandler.ValidateToken(jwtFromJwtHandler, theoryData.ValidationParameters, out SecurityToken validatedToken);
                new JsonWebTokenHandler().ValidateToken(jwtFromJsonHandler, theoryData.ValidationParameters);

                theoryData.ExpectedException.ProcessNoException(context);
                var jwtTokenFromBuilder = new JsonWebToken(jwtFromJwtHandler);
                var jwtTokenFromHandler = new JsonWebToken(jwtFromJsonHandler);
                IdentityComparer.AreEqual(jwtTokenFromBuilder, jwtTokenFromHandler, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateTokenTheoryData> CreateTokenTheoryData
        {
            get
            {
                var tokenHandler = new JwtSecurityTokenHandler
                {
                    SetDefaultTimesOnTokenCreation = false
                };

                tokenHandler.InboundClaimTypeMap.Clear();

                return new TheoryData<CreateTokenTheoryData>
                {
                    new CreateTokenTheoryData
                    {
                        First = true,
                        Payload = Default.Payload,
                        TokenDescriptor =  new SecurityTokenDescriptor
                        {
                            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                            Subject = new ClaimsIdentity(Default.PayloadClaims)
                        },
                        TokenHandler = tokenHandler,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                            ValidAudience = Default.Audience,
                            ValidIssuer = Default.Issuer
                        }
                    },
                };
            }
        }

        // Test checks to make sure that an access token can be successfully validated by the JsonWebTokenHandler.
        // Also ensures that a non-standard claim can be successfully retrieved from the payload and validated.
        [Fact]
        public void ValidateToken()
        {
            IdentityModelEventSource.ShowPII = true;
            TestUtilities.WriteHeader($"{this}.ValidateToken");

            var tokenHandler = new JsonWebTokenHandler();
            var accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwibmJmIjoiMjAxNy0wMy0xOFQxODozMzozNy4wODBaIiwiZXhwIjoiMjAyMS0wMy0xN1QxODozMzozNy4wODBaIn0.JeUhB3r_BBiImzySSQ5qBO0HqE6-mkW5vQDr6Yocfu7pLluAxS854PXMXuIOlbiV9TCQAUDw8UjaxryaCEFRDqfAxl_nfMXn4K7iRc691ft9TL1qw9y40cjc16McBHc-lpu1F0lnXYNW9vGdxkQHpSQLDsVxAzyKXNypLYyNPwlZJp_G1Gx7fuVxOQOyMgZ-wcTx1c-mQmozLVQJ6r8-XC4LLVVotwjTQqZzVRhyPoMFHP_6auPA77P0JaiFnl3KMsASDmE3EMF5iOLBWzR0XqHLB9HNqdp0cVQQroSxvU7YJoE9jVFX6KfHusg5blsudlR0v4vv-1rhL9uFqRDNfw";
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = "http://Default.Audience.com",
                ValidIssuer = "http://Default.Issuer.com",
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };
            var tokenValidationResult = tokenHandler.ValidateToken(accessToken, tokenValidationParameters);
            var jsonWebToken = tokenValidationResult.SecurityToken as JsonWebToken;
            var email = jsonWebToken.Payload.Value<string>(JwtRegisteredClaimNames.Email);

            if (!email.Equals("Bob@contoso.com"))
                throw new SecurityTokenException("Token does not contain the correct value for the 'email' claim.");
        }

        // Test checks to make sure that the token payload retrieved from ValidateToken is the same as the payload
        // the token was initially created with. 
        [Fact]
        public void RoundTripToken()
        {
            IdentityModelEventSource.ShowPII = true;
            TestUtilities.WriteHeader($"{this}.RoundTripToken");
            var context = new CompareContext();

            var tokenHandler = new JsonWebTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = Default.Audience,
                ValidIssuer = Default.Issuer,
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };

            string jwtString = tokenHandler.CreateToken(Default.Payload, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var tokenValidationResult = tokenHandler.ValidateToken(jwtString, tokenValidationParameters);
            var validatedToken = tokenValidationResult.SecurityToken as JsonWebToken;
            IdentityComparer.AreEqual(Default.Payload, validatedToken.Payload, context);
        }
    }

    public class CreateTokenTheoryData : TheoryDataBase
    {
        public JObject Payload { get; set; } 

        public SigningCredentials SigningCredentials { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public JwtSecurityTokenHandler TokenHandler { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }
    }
}
