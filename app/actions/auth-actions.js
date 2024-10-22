"use server";

import { createAuthSession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { createUser } from "@/lib/user";
import { redirect } from "next/navigation";

export default async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  //
  // checking entered data:
  let errors = {};

  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address";
  }

  if (!password.trim().length > 2) {
    errors.password = "Password must be at least 3 characters long";
  }

  if (Object.keys(errors).length > 0) {
    return { errors };
  }

  //
  // hashing password:
  const securedPassword = hashUserPassword(password);

  //
  // checking email duplication
  // if duplicate - send error / if not - save to DB

  try {
    const userId = createUser(email, securedPassword);

    //
    // create session authentication by using lucia
    await createAuthSession(userId);
    // if ok - redirect to needed page
    redirect("/training");
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "It seems like an account for the chosen email already exist",
        },
      };
    }
    throw error;
  }
}

export async function login(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  const existingUser = getUserByEmail(email);

  if (!existingUser) {
    return {
      errors: {
        email: "Could not authenticate user, please check your credentials",
      },
    };
  }

  const isValidPassword = verifyPassword(existingUser.password, password);

  if (!isValidPassword) {
    return {
      errors: {
        password: "Could not authenticate user, please check your credentials",
      },
    };
  }

  await createAuthSession(existingUser.id);
  // if ok - redirect to needed page
  redirect("/training");
}

export async function authHelper(mode, prevState, formData) {
  if (mode === "login") {
    return login(prevState, formData);
  }
  return signup(prevState, formData);
}
