// Author: Sean Pesce
//
// Wrapper class for java.util.regex.Pattern to facilitate querying named capture groups (pre-Java 20)
//
// References:
//   https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/regex/Pattern.html
//   https://stackoverflow.com/a/65012527

package com.seanpesce.regex;


import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class PatternWithNamedGroups {

    final static public Pattern NAMED_GROUP_REGEX = Pattern.compile("\\(\\?<(.+?)>.*?\\)");


    protected Pattern mPattern = null;
    protected ArrayList<String> mGroupNames = null;


    protected PatternWithNamedGroups(Pattern pattern) {
        this.mPattern = pattern;
        this.mGroupNames = new ArrayList<String>();
        if (this.mPattern != null) {
            Matcher matcher = NAMED_GROUP_REGEX.matcher(this.mPattern.pattern());
            while (matcher.find()) {
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    this.mGroupNames.add(matcher.group(i));
                }
            }
        }
    }


    public Pattern getPattern() {
        return this.mPattern;
    }

    public List<String> getGroupNames() {
        return this.mGroupNames;
    }


    public static PatternWithNamedGroups compile(String regex) {
        return new PatternWithNamedGroups(Pattern.compile(regex));
    }

    public static PatternWithNamedGroups compile(String regex, int flags) {
        return new PatternWithNamedGroups(Pattern.compile(regex, flags));
    }

}
