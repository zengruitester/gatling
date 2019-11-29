/*
 * Copyright 2011-2019 GatlingCorp (https://gatling.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.gatling.core.check.jsonpath

import io.gatling.commons.util.Collections
import io.gatling.core.check._

import com.fasterxml.jackson.databind.JsonNode

class JsonPathFindExtractor[X: JsonFilter](name: String, path: String, occurrence: Int, jsonPaths: JsonPaths)
    extends FindCriterionExtractor[JsonNode, String, X](
      name,
      path,
      occurrence,
      jsonPaths.extractAll(_, path).map(Collections.lift(_, occurrence))
    )

class JsonPathFindAllExtractor[X: JsonFilter](name: String, path: String, jsonPaths: JsonPaths)
    extends FindAllCriterionExtractor[JsonNode, String, X](
      name,
      path,
      jsonPaths.extractAll(_, path).map(_.toVector.liftSeqOption)
    )

class JsonPathCountExtractor(name: String, path: String, jsonPaths: JsonPaths)
    extends CountCriterionExtractor[JsonNode, String](
      name,
      path,
      jsonPaths.extractAll[Any](_, path).map(i => Some(i.size))
    )
