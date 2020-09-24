using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace AspNet.Security.OAuth.Esia
{
    static class EsiaExtensions
    {
        public static JsonElement ToJsonElement(this object data)
        {
            using var ms = new MemoryStream();
            
            using (var w = new Utf8JsonWriter(ms))
                JsonSerializer.Serialize(w, data);

            ms.Position = 0;

            return JsonDocument.Parse(ms).RootElement;
        }
    }
}
