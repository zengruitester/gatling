.. _maven-plugin:

############
Maven plugin
############

.. highlight:: xml

Using this plugin, Gatling can be launched when building your project, for example with your favorite Continuous Integration (CI) solution.

Versions
========

Check out available versions on `Maven Central <https://search.maven.org/search?q=g:io.gatling%20AND%20a:gatling-maven-plugin&core=gav>`_.

Beware that milestones (M versions) are not documented for OSS users and are only released for `FrontLine <https://gatling.io/gatling-frontline/>`_ customers.

Setup
=====

In your ``pom.xml``, add::

  <dependencies>
    <dependency>
      <groupId>io.gatling.highcharts</groupId>
      <artifactId>gatling-charts-highcharts</artifactId>
      <version>MANUALLY_REPLACE_WITH_LATEST_VERSION</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <plugin>
    <groupId>io.gatling</groupId>
    <artifactId>gatling-maven-plugin</artifactId>
    <version>MANUALLY_REPLACE_WITH_LATEST_VERSION</version>
  </plugin>

Demo sample
===========

You can find a `sample project demoing the gatling-maven-plugin <https://github.com/gatling/gatling-maven-plugin-demo>`_ in Gatling's Github organization.

You can also use the :ref:`gatling-highcharts-maven-archetype <maven-archetype>` to bootstrap your project.

Usage
=====

.. _maven-goal:

Directly running maven goal
---------------------------

You can directly launch the gatling-maven-plugin with the ``test`` goal::

  mvn gatling:test


The gatling-maven-plugin will take care of compiling your code.

.. _maven-lifecycle:

Running from maven lifecycle
----------------------------

If you want to have the gatling-maven-plugin during maven's phases lifecycle, eg because you want it to be triggered with ``mvn verify``,
you must explicitly configure an execution block::

  <plugin>
    <groupId>io.gatling</groupId>
    <artifactId>gatling-maven-plugin</artifactId>
    <version>MANUALLY_REPLACE_WITH_LATEST_VERSION</version>
    <executions>
      <execution>
        <goals>
          <goal>test</goal>
        </goals>
      </execution>
    </executions>
  </plugin>

The `test` goal is bound by default to the ``integration-test`` phase

.. _maven-advanced-configuration:

Configuration
=============

The example below shows the default values (so don't bother specifying options you don't override!!!)::

  <configuration>
    <simulationClass>foo.Bar</simulationClass>                               <!-- the name of the single Simulation class to run -->
    <runMultipleSimulations>false</runMultipleSimulations>                   <!-- if the plugin should run multiple simulations sequentially -->
    <includes>                                                               <!-- include filters, see dedicated section below -->
      <include></include>
    </includes>
    <excludes>                                                               <!-- exclude filters, see dedicated section below -->
      <exclude></exclude>
    </excludes>
    <noReports>false</noReports>                                             <!-- to disable generating HTML reports -->
    <reportsOnly></reportsOnly>                                              <!-- to only trigger generating HTML reports from the log file contained in folder parameter -->
    <runDescription>This-is-the-run-description</runDescription>             <!-- short text that will be displayed in the HTML reports -->
    <skip>false</skip>                                                       <!-- skip executing this plugin -->
    <failOnError>true</failOnError>                                          <!-- report failure in case of assertion failure, typically to fail CI pipeline -->
    <continueOnAssertionFailure>false</continueOnAssertionFailure>           <!-- keep on executing multiple simulations even if one fails -->
    <useOldJenkinsJUnitSupport>false</useOldJenkinsJUnitSupport>             <!-- report results to Jenkins JUnit support (workaround until we manage to get Gatling support into Jenkins) -->
    <jvmArgs>
      <jvmArg>-DmyExtraParam=foo</jvmArg>                                    <!-- pass extra parameters to the Gatling JVM -->
    </jvmArgs>
    <overrideJvmArgs>false</overrideJvmArgs>                                 <!-- if above option should override the defaults instead of replacing them -->
    <propagateSystemProperties>true</propagateSystemProperties>              <!-- if System properties from the maven JVM should be propagated to the Gatling forked one -->
    <compilerJvmArgs>
      <compilerJvmArg>-DmyExtraParam=foo</compilerJvmArg>                    <!-- pass extra parameters to the Compiler JVM -->
    </compilerJvmArgs>
    <overrideCompilerJvmArgs>false</overrideCompilerJvmArgs>                 <!-- if above option should override the defaults instead of replacing them -->
    <extraScalacOptions>                                                     <!-- extra options to be passed to scalac -->
      <extraScalacOption></extraScalacOption>
    </extraScalacOptions>
    <disableCompiler>false</disableCompiler>                                 <!-- if compiler should be disabled, typically because another plugin has already compiled sources -->
    <simulationsFolder>${project.basedir}/src/test/scala</simulationsFolder> <!-- where the simulations to be compiled are located -->
    <resourcesFolder>${project.basedir}/src/test/resources</resourcesFolder> <!-- where the test resources are located -->
    <resultsFolder>${project.basedir}/target/gatling</resultsFolder>         <!-- where the simulation log and the HTML reports will be generated -->
    <workingDirectory>${project.basedir}</workingDirectory>                  <!-- change working directory to something other than the current working directory -->
  </configuration>

Includes/Excludes filters
-------------------------

When running multiple simulations, you can control which simulations will be triggers with the ``includes`` and ``excludes`` filters.
Those use the ant pattern syntax and are matched against class names.
Also note that those filters are only applied against the classes that were compiled from sources in the project the plugin is set.

::

  <configuration>
    <!--   ...  -->
    <runMultipleSimulations>true</runMultipleSimulations>
    <includes>
      <include>my.package.*</include>
    </includes>
    <excludes>
      <exclude>my.package.IgnoredSimulation</exclude>
    </excludes>
  </configuration>

.. note:: The order of filters has no impact on execution order, simulations will be sorted by class name alphabetically.

Disabling compiler
==================

By default, the gatling-maven-plugin takes care of compiling your Scala code, so you can directly run ``mvn gatling:test``.

Then, for some reason, you might want to have another plugin, such as the `scala-maven-plugin <https://github.com/davidB/scala-maven-plugin>`_
or the `scalor-maven-plugin <https://github.com/random-maven/scalor-maven-plugin>`_, take care of compiling.
Then, you can disable the Gatling compiler so you don't compile twice::

  <configuration>
    <disableCompiler>true</disableCompiler>
  </configuration>

Overriding the logback.xml file
===============================

You can either have a ``logback-test.xml`` that has precedence over the embedded ``logback.xml`` file, or add a JVM option ``-Dlogback.configurationFile=myFilePath``.

Sources
=======

If you're interested in contributing, you can find the `gatling-maven-plugin sources <https://github.com/gatling/gatling-maven-plugin>`_ on Github.
